// tau2-retail-v1: compiled from tau2-bench data/tau2/domains/retail/policy.md
// (sha256 2c9652afbce57d6e087768d37cda64d31c53d50b3e3225cfdb791bac66466467).
// Design notes section 1.3 (this line edited for publication: it gave a local path).

@id("retail.tools.allowlist")
@reason("Only the shop's retail tools may be called (policy.md lines 3 to 8).")
permit (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [
    Tool::"calculate",
    Tool::"find_user_id_by_email",
    Tool::"find_user_id_by_name_zip",
    Tool::"get_user_details",
    Tool::"get_order_details",
    Tool::"get_product_details",
    Tool::"get_item_details",
    Tool::"list_all_product_types",
    Tool::"transfer_to_human_agents",
    Tool::"cancel_pending_order",
    Tool::"modify_pending_order_address",
    Tool::"modify_pending_order_items",
    Tool::"modify_pending_order_payment",
    Tool::"modify_user_address",
    Tool::"return_delivered_order_items",
    Tool::"exchange_delivered_order_items"
  ].contains(resource)
};

// P5a: the same rules with one added comment line (a new digest, no change in meaning).
