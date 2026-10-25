@id("retail.identity.authenticate-first")
@reason("Locate the customer by email, or by name and zip code, before reading a profile or an order or changing anything (policy.md line 10).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [
    Tool::"get_user_details",
    Tool::"get_order_details",
    Tool::"cancel_pending_order",
    Tool::"modify_pending_order_address",
    Tool::"modify_pending_order_items",
    Tool::"modify_pending_order_payment",
    Tool::"modify_user_address",
    Tool::"return_delivered_order_items",
    Tool::"exchange_delivered_order_items"
  ].contains(resource) &&
  !(context has input && context.input has session &&
    context.input.session has auth_user)
};

@id("retail.identity.other-customer-profile")
@reason("One customer per conversation: this call names a user other than the customer who was located (policy.md line 14).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [Tool::"get_user_details", Tool::"modify_user_address"].contains(resource) &&
  context has input && context.input has args && context.input.args has user_id &&
  context.input has session && context.input.session has auth_user &&
  context.input.args.user_id != context.input.session.auth_user
};

@id("retail.identity.other-customer-order")
@reason("One customer per conversation: this order belongs to someone other than the customer who was located (policy.md line 14).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [
    Tool::"cancel_pending_order",
    Tool::"modify_pending_order_address",
    Tool::"modify_pending_order_items",
    Tool::"modify_pending_order_payment",
    Tool::"return_delivered_order_items",
    Tool::"exchange_delivered_order_items"
  ].contains(resource) &&
  context has input && context.input has session &&
  context.input.session has auth_user &&
  context.input.session has order && context.input.session.order has user_id &&
  context.input.session.order.user_id != context.input.session.auth_user
};
