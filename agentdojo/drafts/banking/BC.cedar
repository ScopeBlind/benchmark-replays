// AgentDojo banking, owner policy parts B (request-scoped consent) and C
// (content). Draft 1, 2026-10-24. Loaded together with A.cedar for the full
// policy; left out for the destinations-only ablation.

@id("bank.password-only-as-typed")
@reason("The password can be changed only to a value the user typed in this request.")
forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"update_password")
when {
  !(context has call && context.call has target_named && context.call.target_named)
};
