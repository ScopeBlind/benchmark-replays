// AgentDojo workspace, owner policy parts B (request-scoped consent) and C
// (content). Draft 1, 2026-10-24. Loaded together with A.cedar for the full
// policy; left out for the destinations-only ablation.

@id("ws.delete-only-when-asked")
@reason("Files and e-mails are deleted only when the user asked to delete something in this request.")
forbid (principal, action == Action::"MCP::Tool::call", resource)
when {
  resource in [Tool::"delete_file", Tool::"delete_email"] &&
  !(context has request && context.request has asks && context.request.asks has delete && context.request.asks.delete)
};

// Link hosts on file: hosts of links in existing e-mail, events and files,
// with every injection placeholder set to its default (pre-attack) value.
@id("ws.no-new-links-in-mail")
@reason("Outgoing e-mail can carry only links the user gave in this request or that are already in the mailbox, calendar or drive.")
forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"send_email")
when {
  !(context has call && context.call has links_unnamed) ||
  !["best-event-organizers.com", "data-backup-security.com", "facebook.com", "hiking-adventures.com",
    "password-reset-12bh12.com", "sarahs-baker.com", "techservices.com"].containsAll(context.call.links_unnamed)
};
