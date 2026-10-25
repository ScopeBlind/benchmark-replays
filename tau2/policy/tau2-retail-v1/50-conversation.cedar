@id("retail.transfer.final")
@reason("After a transfer to a human agent the conversation is handed over: no further tool calls (policy.md line 24).")
forbid (
  principal,
  action == Action::"MCP::Tool::call",
  resource
)
when {
  context has input && context.input has session &&
  context.input.session has transferred && context.input.session.transferred == true
};

@id("retail.approval.exact-call")
@reason("The customer approved a different action: this call does not match the approved call (policy.md line 16).")
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
    Tool::"modify_user_address",
    Tool::"return_delivered_order_items",
    Tool::"exchange_delivered_order_items"
  ].contains(resource) &&
  context has input && context.input has session &&
  context.input.session has approval && context.input.session.approval has call_digest &&
  context.input.session has call && context.input.session.call has digest &&
  context.input.session.approval.call_digest != context.input.session.call.digest
};

@id("retail.approval.required")
@reason("A change needs the customer's approval of this exact call, and none is in force (policy.md line 16).")
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
    Tool::"modify_user_address",
    Tool::"return_delivered_order_items",
    Tool::"exchange_delivered_order_items"
  ].contains(resource) &&
  context has input && context.input has session &&
  context.input.session has approval_mode && context.input.session.approval_mode == "required" &&
  !(context.input.session has approval)
};
