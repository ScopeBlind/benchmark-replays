// P5b: retail.order.status-checked-first removed (a relaxation).

@id("retail.cancel.pending-only")
@reason("Only a pending order can be cancelled (policy.md line 88).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"cancel_pending_order"
)
when {
  context has input && context.input has session &&
  context.input.session has order && context.input.session.order has status &&
  context.input.session.order.status != "pending"
};

@id("retail.cancel.reason")
@reason("A cancellation needs the reason 'no longer needed' or 'ordered by mistake' (policy.md line 90).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"cancel_pending_order"
)
unless {
  context has input && context.input has args && context.input.args has reason &&
  ["no longer needed", "ordered by mistake"].contains(context.input.args.reason)
};

@id("retail.modify.pending-only")
@reason("Only a pending order can be modified, and not after its items were changed (policy.md lines 96 and 110).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [
    Tool::"modify_pending_order_address",
    Tool::"modify_pending_order_items",
    Tool::"modify_pending_order_payment"
  ].contains(resource) &&
  context has input && context.input has session &&
  context.input.session has order && context.input.session.order has status &&
  context.input.session.order.status != "pending"
};

@id("retail.return-exchange.delivered-only")
@reason("Only a delivered order can be returned or exchanged (policy.md lines 118 and 130).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  [Tool::"return_delivered_order_items", Tool::"exchange_delivered_order_items"].contains(resource) &&
  context has input && context.input has session &&
  context.input.session has order && context.input.session.order has status &&
  context.input.session.order.status != "delivered"
};
