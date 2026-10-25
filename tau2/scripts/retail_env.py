"""Reference retail environment: an independent port of tau2-bench's retail tools.

Standard library only; imports nothing from tau2. Write tools follow
src/tau2/domains/retail/tools.py at v1.0.1 (identical to HEAD 0c69df45 for every
write tool) line by line, including the order in which state is mutated, so a
tool that raises part way leaves the same partial state. Read tools follow
v1.0.1 (lower-case lookups, first match). `calculate` is never evaluated.

The database is held as plain dicts in pydantic `model_dump()` form, so the
hash is tau2's: sha256(json.dumps(dump, sort_keys=True, default=str)).
"""
import copy
import hashlib
import json

FLOAT = float

WRITE_TOOLS = (
    "cancel_pending_order",
    "exchange_delivered_order_items",
    "modify_pending_order_address",
    "modify_pending_order_items",
    "modify_pending_order_payment",
    "modify_user_address",
    "return_delivered_order_items",
)
READ_TOOLS = (
    "find_user_id_by_email",
    "find_user_id_by_name_zip",
    "get_order_details",
    "get_product_details",
    "get_item_details",
    "get_user_details",
    "list_all_product_types",
)
GENERIC_TOOLS = ("calculate", "transfer_to_human_agents")
ALL_TOOLS = WRITE_TOOLS + READ_TOOLS + GENERIC_TOOLS
ORDER_FIELDS_OPTIONAL = (
    "cancel_reason",
    "exchange_items",
    "exchange_new_items",
    "exchange_payment_method_id",
    "exchange_price_difference",
    "return_items",
    "return_payment_method_id",
)


class ToolError(Exception):
    """Raised by a tool; the message becomes 'Error: <message>'."""


def _addr(a):
    return {k: a[k] for k in ("address1", "address2", "city", "country", "state", "zip")}


def _pm(m):
    src = m["source"]
    if src == "credit_card":
        return {"source": src, "id": m["id"], "brand": m["brand"], "last_four": m["last_four"]}
    if src == "gift_card":
        return {"source": src, "id": m["id"], "balance": FLOAT(m["balance"])}
    if src == "paypal":
        return {"source": src, "id": m["id"]}
    raise ValueError(f"unknown payment source {src!r}")


def normalize_db(raw):
    """Return the database in RetailDB.model_dump() form (fields, types, nulls)."""
    products = {}
    for pid, p in raw["products"].items():
        products[pid] = {
            "name": p["name"],
            "product_id": p["product_id"],
            "variants": {
                vid: {"item_id": v["item_id"], "options": dict(v["options"]), "available": bool(v["available"]),
                      "price": FLOAT(v["price"])}
                for vid, v in p["variants"].items()
            },
        }
    users = {}
    for uid, u in raw["users"].items():
        users[uid] = {
            "user_id": u["user_id"],
            "name": {"first_name": u["name"]["first_name"], "last_name": u["name"]["last_name"]},
            "address": _addr(u["address"]),
            "email": u["email"],
            "payment_methods": {k: _pm(m) for k, m in u["payment_methods"].items()},
            "orders": list(u["orders"]),
        }
    orders = {}
    for oid, o in raw["orders"].items():
        d = {
            "order_id": o["order_id"],
            "user_id": o["user_id"],
            "address": _addr(o["address"]),
            "items": [{"name": i["name"], "product_id": i["product_id"], "item_id": i["item_id"],
                       "price": FLOAT(i["price"]), "options": dict(i["options"])} for i in o["items"]],
            "status": o["status"],
            "fulfillments": [{"tracking_id": list(f["tracking_id"]), "item_ids": list(f["item_ids"])}
                             for f in o["fulfillments"]],
            "payment_history": [{"transaction_type": p["transaction_type"], "amount": FLOAT(p["amount"]),
                                 "payment_method_id": p["payment_method_id"]} for p in o["payment_history"]],
        }
        for k in ORDER_FIELDS_OPTIONAL:
            v = o.get(k)
            if k == "exchange_price_difference" and v is not None:
                v = FLOAT(v)
            d[k] = v
        orders[oid] = d
    return {"products": products, "users": users, "orders": orders}


def db_hash(db):
    s = json.dumps(db, sort_keys=True, default=str)
    return hashlib.sha256(s.encode()).hexdigest()


def record_hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def diff_paths(a, b, prefix=""):
    """Paths where two JSON-like values differ (dict keys and list positions)."""
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            p = f"{prefix}[{k}]" if prefix else str(k)
            if k not in a or k not in b:
                out.append(p)
            else:
                out.extend(diff_paths(a[k], b[k], p))
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(prefix)
        else:
            for i, (x, y) in enumerate(zip(a, b)):
                out.extend(diff_paths(x, y, f"{prefix}[{i}]"))
    else:
        if a != b or type(a) is not type(b):
            out.append(prefix)
    return out


def db_diff(final, gold):
    """Entity-level differences: (collection, id, field paths)."""
    out = []
    for coll in ("orders", "users", "products"):
        fa, ga = final[coll], gold[coll]
        for k in sorted(set(fa) | set(ga)):
            if k not in fa or k not in ga:
                out.append({"collection": coll, "id": k, "fields": ["<missing>"]})
                continue
            if fa[k] != ga[k] or record_hash(fa[k]) != record_hash(ga[k]):
                fields = sorted({p.split("[")[0] if p else "" for p in diff_paths(fa[k], ga[k])} - {""})
                paths = diff_paths(fa[k], ga[k])
                out.append({"collection": coll, "id": k, "fields": fields, "paths": paths[:20]})
    return out


class RetailTools:  # mirrors tau2's class name so Python's argument errors read the same
    """All the tools for the retail domain (port)."""

    def __init__(self, db):
        self.db = db

    # helpers -----------------------------------------------------------
    def _get_order(self, order_id):
        if order_id not in self.db["orders"]:
            raise ToolError("Order not found")
        return self.db["orders"][order_id]

    def _get_user(self, user_id):
        if user_id not in self.db["users"]:
            raise ToolError("User not found")
        return self.db["users"][user_id]

    def _get_product(self, product_id):
        if product_id not in self.db["products"]:
            raise ToolError("Product not found")
        return self.db["products"][product_id]

    def _get_item(self, item_id):
        for _, product in self.db["products"].items():
            if item_id in product["variants"]:
                return product["variants"][item_id]
        raise ToolError("Item not found")

    def _get_variant(self, product_id, variant_id):
        product = self._get_product(product_id)
        if variant_id not in product["variants"]:
            raise ToolError("Variant not found")
        return product["variants"][variant_id]

    def _get_payment_method(self, user_id, payment_method_id):
        user = self._get_user(user_id)
        if payment_method_id not in user["payment_methods"]:
            raise ToolError("Payment method not found")
        return user["payment_methods"][payment_method_id]

    @staticmethod
    def _is_pending_order(order):
        return "pending" in order["status"]

    @staticmethod
    def _order_payment(transaction_type, amount, payment_method_id):
        # OrderPayment(...) validates: amount must be a number (int becomes float), id a string
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise ToolError("1 validation error for OrderPayment amount")
        if not isinstance(payment_method_id, str):
            raise ToolError("1 validation error for OrderPayment payment_method_id")
        return {"transaction_type": transaction_type, "amount": FLOAT(amount), "payment_method_id": payment_method_id}

    @staticmethod
    def _user_address(address1, address2, city, state, country, zip):
        vals = {"address1": address1, "address2": address2, "city": city, "country": country, "state": state, "zip": zip}
        for k, v in vals.items():
            if not isinstance(v, str):
                raise ToolError(f"1 validation error for UserAddress {k}")
        return vals

    # tools ---------------------------------------------------------------
    def calculate(self, expression):
        raise RuntimeError("calculate is never evaluated by the reference environment")

    def cancel_pending_order(self, order_id, reason):
        order = self._get_order(order_id)
        if order["status"] != "pending":
            raise ToolError("Non-pending order cannot be cancelled")
        if reason not in {"no longer needed", "ordered by mistake"}:
            raise ToolError("Invalid reason")
        refunds = []
        for payment in order["payment_history"]:
            payment_id = payment["payment_method_id"]
            refund = self._order_payment("refund", payment["amount"], payment_id)
            refunds.append(refund)
            user = self._get_user(order["user_id"])
            payment_method = self._get_payment_method(user["user_id"], payment_id)
            if payment_method["source"] == "gift_card":
                payment_method["balance"] += payment["amount"]
                payment_method["balance"] = round(payment_method["balance"], 2)
        order["status"] = "cancelled"
        order["cancel_reason"] = reason
        order["payment_history"].extend(refunds)
        return order

    def exchange_delivered_order_items(self, order_id, item_ids, new_item_ids, payment_method_id):
        order = self._get_order(order_id)
        if order["status"] != "delivered":
            raise ToolError("Non-delivered order cannot be exchanged")
        all_item_ids = [item["item_id"] for item in order["items"]]
        for item_id in item_ids:
            if item_ids.count(item_id) > all_item_ids.count(item_id):
                raise ToolError(f"Number of {item_id} not found.")
        if len(item_ids) != len(new_item_ids):
            raise ToolError("The number of items to be exchanged should match.")
        diff_price = 0
        for item_id, new_item_id in zip(item_ids, new_item_ids):
            item = next((item for item in order["items"] if item["item_id"] == item_id), None)
            if item is None:
                raise ToolError(f"Item {item_id} not found")
            product_id = item["product_id"]
            variant = self._get_variant(product_id, new_item_id)
            if not variant["available"]:
                raise ToolError(f"New item {new_item_id} not found or available")
            old_price = item["price"]
            new_price = variant["price"]
            diff_price += new_price - old_price
        diff_price = round(diff_price, 2)
        payment_method = self._get_payment_method(order["user_id"], payment_method_id)
        if payment_method["source"] == "gift_card" and payment_method["balance"] < diff_price:
            raise ToolError("Insufficient gift card balance to pay for the price difference")
        order["status"] = "exchange requested"
        order["exchange_items"] = sorted(item_ids)
        order["exchange_new_items"] = sorted(new_item_ids)
        order["exchange_payment_method_id"] = payment_method_id
        order["exchange_price_difference"] = diff_price
        return order

    def find_user_id_by_name_zip(self, first_name, last_name, zip):
        for user_id, user in self.db["users"].items():
            if (user["name"]["first_name"].lower() == first_name.lower()
                    and user["name"]["last_name"].lower() == last_name.lower()
                    and user["address"]["zip"] == zip):
                return user_id
        raise ToolError("User not found")

    def find_user_id_by_email(self, email):
        for user_id, user in self.db["users"].items():
            if user["email"].lower() == email.lower():
                return user_id
        raise ToolError("User not found")

    def get_order_details(self, order_id):
        return self._get_order(order_id)

    def get_product_details(self, product_id):
        return self._get_product(product_id)

    def get_item_details(self, item_id):
        return self._get_item(item_id)

    def get_user_details(self, user_id):
        return self._get_user(user_id)

    def list_all_product_types(self):
        product_dict = {p["name"]: p["product_id"] for p in self.db["products"].values()}
        return json.dumps(product_dict, sort_keys=True)

    def modify_pending_order_address(self, order_id, address1, address2, city, state, country, zip):
        order = self._get_order(order_id)
        if not self._is_pending_order(order):
            raise ToolError("Non-pending order cannot be modified")
        order["address"] = self._user_address(address1, address2, city, state, country, zip)
        return order

    def modify_pending_order_items(self, order_id, item_ids, new_item_ids, payment_method_id):
        order = self._get_order(order_id)
        if order["status"] != "pending":
            raise ToolError("Non-pending order cannot be modified")
        all_item_ids = [item["item_id"] for item in order["items"]]
        for item_id in item_ids:
            if item_ids.count(item_id) > all_item_ids.count(item_id):
                raise ToolError(f"{item_id} not found")
        if len(item_ids) != len(new_item_ids):
            raise ToolError("The number of items to be exchanged should match")
        diff_price = 0
        variant = None
        for item_id, new_item_id in zip(item_ids, new_item_ids):
            if item_id == new_item_id:
                raise ToolError("The new item id should be different from the old item id")
            item = next((item for item in order["items"] if item["item_id"] == item_id), None)
            if item is None:
                raise ToolError(f"Item {item_id} not found")
            product_id = item["product_id"]
            variant = self._get_variant(product_id, new_item_id)
            if not variant["available"]:
                raise ToolError(f"New item {new_item_id} not found or available")
            old_price = item["price"]
            new_price = variant["price"]
            diff_price += new_price - old_price
        payment_method = self._get_payment_method(order["user_id"], payment_method_id)
        if payment_method["source"] == "gift_card" and payment_method["balance"] < diff_price:
            raise ToolError("Insufficient gift card balance to pay for the new item")
        order["payment_history"].append(
            self._order_payment("payment" if diff_price > 0 else "refund", abs(diff_price), payment_method_id))
        if payment_method["source"] == "gift_card":
            payment_method["balance"] -= diff_price
            payment_method["balance"] = round(payment_method["balance"], 2)
        for item_id, new_item_id in zip(item_ids, new_item_ids):
            item = next((item for item in order["items"] if item["item_id"] == item_id), None)
            if item is None:
                raise ToolError(f"Item {item_id} not found")
            item["item_id"] = new_item_id
            # tau2 quirk kept on purpose: `variant` is the last one from the loop above
            item["price"] = variant["price"]
            item["options"] = copy.deepcopy(variant["options"])
        order["status"] = "pending (item modified)"
        return order

    def modify_pending_order_payment(self, order_id, payment_method_id):
        order = self._get_order(order_id)
        if not self._is_pending_order(order):
            raise ToolError("Non-pending order cannot be modified")
        payment_method = self._get_payment_method(order["user_id"], payment_method_id)
        if len(order["payment_history"]) != 1 or order["payment_history"][0]["transaction_type"] != "payment":
            raise ToolError("There should be exactly one payment for a pending order")
        if order["payment_history"][0]["payment_method_id"] == payment_method_id:
            raise ToolError("The new payment method should be different from the current one")
        amount = order["payment_history"][0]["amount"]
        if payment_method["source"] == "gift_card" and payment_method["balance"] < amount:
            raise ToolError("Insufficient gift card balance to pay for the order")
        order["payment_history"].extend([
            self._order_payment("payment", amount, payment_method_id),
            self._order_payment("refund", amount, order["payment_history"][0]["payment_method_id"]),
        ])
        if payment_method["source"] == "gift_card":
            payment_method["balance"] -= amount
            payment_method["balance"] = round(payment_method["balance"], 2)
        old_payment_method = self._get_payment_method(order["user_id"], order["payment_history"][0]["payment_method_id"])
        if old_payment_method["source"] == "gift_card":
            old_payment_method["balance"] += amount
            old_payment_method["balance"] = round(old_payment_method["balance"], 2)
        return order

    def modify_user_address(self, user_id, address1, address2, city, state, country, zip):
        user = self._get_user(user_id)
        user["address"] = self._user_address(address1, address2, city, state, country, zip)
        return user

    def return_delivered_order_items(self, order_id, item_ids, payment_method_id):
        order = self._get_order(order_id)
        if order["status"] != "delivered":
            raise ToolError("Non-delivered order cannot be returned")
        user = self._get_user(order["user_id"])
        payment_method = self._get_payment_method(user["user_id"], payment_method_id)
        if payment_method["source"] != "gift_card" and payment_method_id != order["payment_history"][0]["payment_method_id"]:
            raise ToolError("Payment method should be the original payment method")
        all_item_ids = [item["item_id"] for item in order["items"]]
        for item_id in item_ids:
            if item_ids.count(item_id) > all_item_ids.count(item_id):
                raise ToolError("Some item not found")
        order["status"] = "return requested"
        order["return_items"] = sorted(item_ids)
        order["return_payment_method_id"] = payment_method_id
        return order

    def transfer_to_human_agents(self, summary):
        return "Transfer successful"


class Env:
    """One environment: a database plus the tools that act on it."""

    def __init__(self, base_db):
        self.db = copy.deepcopy(base_db)
        self.tools = RetailTools(self.db)

    def call(self, name, arguments):
        """Run a tool the way tau2's Environment.get_response does.

        Returns (content, error): content is the JSON text tau2 would record.
        """
        if name not in ALL_TOOLS:
            return f"Error: Tool '{name}' not found.", True
        if name == "calculate":
            raise RuntimeError("calculate must not be executed")
        fn = getattr(self.tools, name)
        try:
            if not isinstance(arguments, dict):
                raise ToolError("arguments are not an object")
            resp = fn(**arguments)
        except (ToolError, TypeError, KeyError, AttributeError, IndexError, ValueError) as e:
            msg = str(e)
            if isinstance(e, KeyError):
                msg = repr(e.args[0]) if e.args else "KeyError"
            return f"Error: {msg}", True
        if isinstance(resp, str):
            return resp, False
        return json.dumps(resp, default=str), False

    def hash(self):
        return db_hash(self.db)


def load_db(path):
    with open(path, "r", encoding="utf-8") as fh:
        return normalize_db(json.load(fh))


def gold_env(base_db, actions):
    """Replay gold actions on a fresh environment, skipping any that fail (tau2 logs and continues)."""
    env = Env(base_db)
    failed = []
    for i, a in enumerate(actions or []):
        name = a.get("name")
        if name in GENERIC_TOOLS or name in READ_TOOLS:
            # reads and generic tools do not change state; calculate is never evaluated
            continue
        content, err = env.call(name, a.get("arguments") or {})
        if err:
            failed.append({"index": i, "name": name, "error": content})
    return env, failed


def parse_content(content):
    try:
        return json.loads(content)
    except Exception:
        return content
