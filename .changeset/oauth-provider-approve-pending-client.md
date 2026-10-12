---
"@better-auth/oauth-provider": minor
---

Add `approvePendingClient` so a self-registered client stays pending until a user consents, and your application decides who owns it. With the option defined, a client created by open dynamic registration or discovered through CIMD is stored as pending. A pending client cannot obtain tokens, and open registration may request the `client_credentials` grant. When a user accepts consent, the callback sets the owner (`clientReference`) and the `client_credentials` scope ceiling in the same transaction as the consent. A client that already has an owner is never reassigned, and only one of two concurrent approvals succeeds. The callback proves control: Better Auth does not decide who owns the client. Without the option, behavior is unchanged. Adds an optional `pending` column to `oauthClient`, so run your migration.
