# Changelog

All notable changes to `auth-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial public release.

### Added

- Headless, multi-guard authentication through the `Authentication` facade: password, magic-link,
  email-code and passwordless passkey login.
- Multi-step login challenges for TOTP or recovery-code second factors, passkey second factors
  and forced two-factor or passkey enrolment.
- RS256 access tokens with rotating refresh tokens and device sessions, including logout of one
  session, all others or everywhere — built on jwt-for-laravel and refresh-tokens-for-laravel.
- Registration and invitations (`register()`, `invitations()->create()/accept()`).
- Email verification and verified email change.
- Forgot, reset and change password with a password policy and an optional breached-password check.
- Per-account locale and time zone, plus re-authentication for sensitive actions.
- Login-activity log with throttling, lockout, new-device detection and risk hooks.
- Opt-in JSON endpoints for every flow, with uniform error codes and route middleware
  (`authentication.verified`, `authentication.reauthenticated`, …).
- 18 mail notifications, swappable per guard, and an event for every state change.
- Artisan commands `authentication:install`, `authentication:guard`, `authentication:check`,
  `authentication:prune` and `authentication:logout-everywhere`.
- `InteractsWithAuthentication` test helpers (`actingAsAccount()` with a real token pair,
  `assertLoginActivity()`, `assertTokensInvalidated()`).
- One API in three layers: the `Authentication` facade, the injectable
  `AuthenticationManager` and the action classes, all running the same code. Per-guard
  sub-contexts `twoFactor()`, `passkeys()`, `passwords()`, `email()`, `invitations()`,
  `reauthentication()` and `challenges()`, plus `lock()`, `updateLocale()`, `activity()`,
  `contextFrom()` and `tokenFrom()` on every guard and `Authentication::prune()`. Every
  per-guard method also works without `guard()` on the default guard
  (`Authentication::twoFactor()->status($user)`).
- `invitations()->create()` returns the `InvitationLink` it mailed (or, with `send: false`,
  the link for the host to deliver); `invitations()->link()` mints a copyable link without
  mailing it.
- `reauthentication()->ensureFor(SensitiveAction, …)` runs the HTTP layer's sensitive-action
  gate for host code acting on behalf of the signed-in user.

### Changed

- `completeChallenge()`, `invite()` and `acceptInvitation()` moved to
  `challenges()->complete()`, `invitations()->create()` and `invitations()->accept()`.
- The admin/CLI forms of the credential changes need no caller token: `$current` and
  `$context` are optional in the two-factor and passkey actions.
- `ResendInvitation`, `RevokeInvitation` and `SendInvitation` take the guard name first.
- Building-block actions are tagged `@internal`; host code issues tokens through
  `issueTokens()` (`IssueAccountTokens`), which announces them with `TokensIssued` — also for
  `actingAsAccount()`.

### Fixed

- Every action taking an account refuses one of another guard's model before it writes —
  setting or changing a password, two-factor and passkey changes, disabling, locking,
  unlocking and locale updates no longer write first and fail afterwards.
- Resending, revoking or re-linking another guard's invitation is refused.
- A manual `lock()` notifies the owner exactly like the automatic lockout.
- `email_change.require_reauthentication = false` now also switches off
  `ensureFor(SensitiveAction::ChangeEmail)`, not only the HTTP endpoint.
- A login challenge takes its attempt before a TOTP or recovery code is checked, so a parallel
  burst can no longer check more codes than `challenge.max_attempts` allows.
- The risk step-up (`require_second_factor`) applies to magic-link, email-code, invitation and
  registration logins also when `two_factor.after_email_login` is off; a passkey login that
  does not count as MFA must add TOTP.
- Registration no longer skips required two-factor enrolment when
  `two_factor.after_email_login` is off.
- `POST invitations` returns the link (`url`), and a link created without mailing
  (`send: false`, `link()`) no longer counts as a send.
- A refresh retires the session's previous access token, so revoking a session kills every
  access token it minted.
- `reauthentication.methods` is checked against the factor that actually matched (a recovery
  code sent as `totp`).
- A re-authentication no longer makes its device known to new-device detection.
- The users-table stub also adds the passkey user handle, so a fresh install passes
  `authentication:check`.
- On/off settings set from `.env` as `0`/`off`/`no` were cast to true
  (`AUTHENTICATION_LOGIN_PASSWORD=off` left password login on). Every guard switch is now parsed
  as a boolean.
