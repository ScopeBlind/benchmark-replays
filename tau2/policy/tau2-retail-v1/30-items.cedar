@id("retail.items.once-per-order")
@reason("Exchange and item changes can be made once per order, so every item goes in one call (policy.md lines 84 and 110).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [Tool::"modify_pending_order_items", Tool::"exchange_delivered_order_items"].contains(resource) &&
  context has input && context.input has session &&
  context.input.session has prior_item_changes_on_order &&
  context.input.session.prior_item_changes_on_order > 0
};

@id("retail.items.different-option")
@reason("Each new item must be a different option from the item it replaces (policy.md lines 112 and 132).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [Tool::"modify_pending_order_items", Tool::"exchange_delivered_order_items"].contains(resource) &&
  context has input && context.input has session && context.input.session has call &&
  context.input.session.call has same_item_count &&
  context.input.session.call.same_item_count > 0
};

@id("retail.items.available-same-product")
@reason("Each new item must be an available variant of the same product (policy.md lines 62, 112 and 132).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [Tool::"modify_pending_order_items", Tool::"exchange_delivered_order_items"].contains(resource) &&
  context has input && context.input has session && context.input.session has call &&
  context.input.session.call has bad_new_item_count &&
  context.input.session.call.bad_new_item_count > 0
};

@id("retail.items.in-order")
@reason("Every item named must be in the order, as many times as named (implied by policy.md lines 112, 120 and 130).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [
    Tool::"return_delivered_order_items",
    Tool::"exchange_delivered_order_items",
    Tool::"modify_pending_order_items"
  ].contains(resource) &&
  context has input && context.input has session && context.input.session has call &&
  context.input.session.call has missing_item_count &&
  context.input.session.call.missing_item_count > 0
};
