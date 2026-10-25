@id("retail.return.refund-destination")
@reason("A return refund goes to the original payment method or to one of the customer's gift cards (policy.md line 124).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"return_delivered_order_items"
)
when {
  context has input && context.input has args && context.input.args has payment_method_id &&
  context.input has session && context.input.session has order &&
  context.input.session.order has original_payment_method &&
  context.input.args.payment_method_id != context.input.session.order.original_payment_method &&
  !(context.input.session has payment_method &&
    context.input.session.payment_method has source &&
    context.input.session.payment_method.source == "gift_card" &&
    context.input.session.payment_method has owner &&
    context.input.session has auth_user &&
    context.input.session.payment_method.owner == context.input.session.auth_user)
};

@id("retail.payment.customer-method")
@reason("The payment method must be the order's original method or one of the located customer's own methods (policy.md lines 102, 114, 122 and 134).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [
    Tool::"return_delivered_order_items",
    Tool::"exchange_delivered_order_items",
    Tool::"modify_pending_order_items",
    Tool::"modify_pending_order_payment"
  ].contains(resource) &&
  context has input && context.input has args && context.input.args has payment_method_id &&
  !(context.input has session && context.input.session has payment_method &&
    context.input.session.payment_method has owner &&
    context.input.session has auth_user &&
    context.input.session.payment_method.owner == context.input.session.auth_user) &&
  !(context.input has session && context.input.session has order &&
    context.input.session.order has original_payment_method &&
    context.input.session.order.original_payment_method == context.input.args.payment_method_id)
};

@id("retail.payment.gift-card-balance")
@reason("A gift card that pays must cover the amount (policy.md lines 104, 114 and 134).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [
    Tool::"exchange_delivered_order_items",
    Tool::"modify_pending_order_items",
    Tool::"modify_pending_order_payment"
  ].contains(resource) &&
  context has input && context.input has session &&
  context.input.session has payment_method &&
  context.input.session.payment_method has source &&
  context.input.session.payment_method.source == "gift_card" &&
  context.input.session.payment_method has balance_cents &&
  context.input.session has call && context.input.session.call has charge_cents &&
  context.input.session.payment_method.balance_cents < context.input.session.call.charge_cents
};

@id("retail.payment.change-must-differ")
@reason("A payment change must name a method other than the original one (policy.md line 102).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"modify_pending_order_payment"
)
when {
  context has input && context.input has args && context.input.args has payment_method_id &&
  context.input has session && context.input.session has order &&
  context.input.session.order has original_payment_method &&
  context.input.args.payment_method_id == context.input.session.order.original_payment_method
};
