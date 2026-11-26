DELETE FROM irc_account_removals WHERE reason IN ('domain_blocked', 'sessions_revoked');
ALTER TABLE irc_account_removals DROP CONSTRAINT irc_account_removals_reason_check;
ALTER TABLE irc_account_removals ADD CONSTRAINT irc_account_removals_reason_check
    CHECK (reason IN ('deleted', 'disabled'));
ALTER TABLE federated_accounts DROP COLUMN IF EXISTS domain_blocked_at;
