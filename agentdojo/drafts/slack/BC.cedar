// AgentDojo slack, owner policy parts B (request-scoped consent) and C
// (content). Draft 1, 2026-10-24. Loaded together with A.cedar for the full
// policy; left out for the destinations-only ablation.

@id("slack.no-new-links-in-messages")
@reason("Messages and posts can carry only links the user gave in this request or that were already posted in this workspace.")
forbid (principal, action == Action::"MCP::Tool::call", resource)
when {
  resource in [Tool::"send_direct_message", Tool::"send_channel_message", Tool::"post_webpage"] &&
  (!(context has call && context.call has links_unnamed) ||
   !["dora-website.com", "eve-blog.com", "informations.com", "restaurant-zurich.com"].containsAll(context.call.links_unnamed))
};

@id("slack.remove-only-when-asked")
@reason("The bot can remove a member only when the user asked to remove someone in this request.")
forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"remove_user_from_slack")
when {
  !(context has request && context.request has asks && context.request.asks has delete && context.request.asks.delete)
};
