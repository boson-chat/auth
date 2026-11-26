-- A domain block drops the domain's federated users from IRC
-- (docs/federation.md "IRC, voice and files").
--
-- domain_blocked_at: set while the account's home domain is on the
-- effective block list and the disconnect was queued; cleared when the
-- domain is unblocked. The account itself (users.disabled_at) is never
-- touched, so unblocking restores everything.
ALTER TABLE federated_accounts ADD COLUMN domain_blocked_at timestamptz;

-- Two more kinds of irc_account_removals rows, written by auth (not by
-- triggers) and served on the feed as reason "disabled" (disconnect, keep
-- the account):
--   domain_blocked:   the home domain was blocked; applies while it still is
--   sessions_revoked: POST /v1/admin/federation/domains/{d}/revoke-sessions;
--                     applies until the user signs in again
ALTER TABLE irc_account_removals DROP CONSTRAINT irc_account_removals_reason_check;
ALTER TABLE irc_account_removals ADD CONSTRAINT irc_account_removals_reason_check
    CHECK (reason IN ('deleted', 'disabled', 'domain_blocked', 'sessions_revoked'));
