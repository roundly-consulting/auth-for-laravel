# Changelog

All notable changes to `auth-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

## 1.1.1 - 2026-10-07

### Added

- `authentication:check` warns when `two-factor.attempts` is `null` on a guard with two-factor on: two-factor's per-account limiter is then off, the per-challenge `challenge.max_attempts` is the only bound on second-factor codes, and every new login opens a fresh budget.

### Changed

- `two_factor.after_email_login = false` now exempts magic-link, email-code and invitation logins from the second-factor policy only; `passkeys.mode = required` still makes them enrol a passkey. Before, the setting skipped the mandated enrolment too, so `required` could never be enforced for accounts that only sign in by email.
- Registering two guards on the same effective route prefix or route-name prefix (from `routes.*`, a manual `Authentication::routes()` call or `->prefix()` / `->name()`) now throws `AuthenticationMisconfigured` naming both guards. Before, Laravel silently kept only the last route per URL and `route:cache` refused the duplicate name. Upgrade: give each routed guard its own `routes.prefix` and `routes.name`.
- Registration and invitation acceptance send the "account exists" notice in the address holder's `preferredLocale()`, falling back to the request's / invitation's locale.
- Documentation: `EmailChangeRequested` fires only when a confirmation link was issued; it is server-side and must never be shown to the requester.

### Fixed

- `AUTHENTICATION_PASSKEYS=off` with the shipped config no longer fails validation for every guard on the defaults (every endpoint answered 500). `passkeys.second_factor = allowed` is accepted with passkeys off; `required` and `required_when_enrolled` are still refused.
- A lock written while a password login was still hashing now refuses that login, even with the correct password. Failures checked against an account loaded before the lock no longer count, so concurrent failures lock and notify exactly once.
- `challenge.max_active_per_account` now holds when logins race: older challenges are superseded again after the new one is inserted.
- An email change to a taken address now also sends `EmailChangeRequestedNotification` to the old address (with `email_change.notify_old`), so the requester's own mailbox no longer shows whether the address is in use. Its "account exists" notice shares the 10-minute per-address cooldown with registration and invitation acceptance, and goes out in the holder's `preferredLocale()`, falling back to the requester's.
- Removing a passkey locks the account row while it counts and revokes, so two concurrent removes can no longer delete an account's last way in.
- An explicit re-authentication now satisfies `authentication.reauthenticated:N` routes whose window is longer than `reauthentication.timeout` (the proof is kept for the longer of the timeout and the refresh-token TTL); `confirmed_until` is unchanged.
- `authentication:check` lists a wrongly typed config value (a non-string class key, `notifications.classes.* = false`, an invalid `*.key_type`, another guard's bad `laravel_guard`) as a problem instead of crashing and hiding the rest.
- `authentication:guard`: a re-run no longer adds a second `create_<table>_table` migration (an existing one makes it refuse; `--force` overwrites it in place); `--table` is validated like the guard name, and an invalid one writes nothing; the migration, model and factory use the configured `authentication.columns.password` / `email_verified_at` names.
- Models using `HasAuthentication` also hide the password column when `authentication.columns.password` is renamed.
- `assertTokensInvalidated()` under scope `all` judges only the sessions active when `actingAsAccount()` signed the account in, so a login after the invalidation (`passwords.reset.login_after`) no longer fails it. Without a guard it resolves the guard like `actingAsAccount()`: an account of another guard throws instead of being judged by the default guard's scope, which could pass a missing invalidation.

### Security

- A login that raced a password reset, a disable or a logout everywhere no longer leaves a session that keeps refreshing. Sessions record the token version they were issued under; refreshing one the account has moved past revokes it and answers `refresh_invalid`. Sessions issued by 1.1.0 or earlier carry no version and are not checked.
- A correct password that login refuses with the uniform `invalid_credentials` (a disabled or unverified account without `reveal_account_state`, a uniform risk denial, an unavailable step-up) now counts against the login throttle like a wrong one and leaves the lockout counter alone, so the throttle no longer reveals which guess was right.
- A passkey second factor or forced passkey enrolment that loses a race to a restarted ceremony now answers `challenge_invalid` instead of skipping the next step; a passkey-plus-TOTP setup could finish without TOTP.

## 1.1.0 - 2026-10-05

### Added

- `SignInBlockedNotification` (`notifications.classes.sign_in_blocked`, risk reaction `deny`) and `UnusualSignInNotification` (`notifications.classes.unusual_sign_in`, risk reaction `notify`), with `NotificationType::SignInBlocked` / `UnusualSignIn` and English and Slovak copy. A published config that lacks the new keys still sends them; set one to `null` to switch it off.
- `InvitationSendLimitReached` (422, `invitation_send_limit`) for a resend past `invitations.max_sends`.

### Changed

- Risk alerts no longer go out as the refresh-token-reuse email (`SuspiciousSessionNotification`), whose text said the affected session had been signed out — untrue for a blocked sign-in (no session existed) and for an unusual one (its session is live). A host that swapped or disabled `notifications.classes.refresh_token_reuse` to change the risk alerts now configures `sign_in_blocked` / `unusual_sign_in` instead. The `notifications.refresh_token_reuse.reasons.blocked_sign_in` / `unusual_sign_in` lines are gone.
- Resending an invitation past `max_sends` throws `InvitationSendLimitReached` (422) instead of `TooManyAttempts` with a `Retry-After` of the whole invitation TTL — the count never resets, so no retry could succeed. Upgrade: catch `InvitationSendLimitReached` (code `invitation_send_limit`) wherever a resend's `TooManyAttempts` was handled.
- Documentation: the README banner uses an absolute image URL, so it also renders on Packagist and other sites.

### Fixed

- The `notifications.expiry` plural line also covers a count of 0, so it never renders with a leading space.
- Concurrent requests could all pass a per-account cooldown (the verification resend and the "account exists" notice) and each send a mail; the cooldown is now one atomic increment.
- Concurrent invitation resends could each mail, ignore the resend cooldown and `max_sends`, and under-count `send_count`; the count is now incremented in SQL, capped at `max_sends`, and the cooldown window is reserved atomically.
- Accepting an invitation with a taken address (`invitations.lock_email = false`) mailed that address an "account exists" notice every time; it now shares registration's 10-minute per-address cooldown.
- Two failed logins reaching `lockout.threshold` together both locked the account, dispatching `AccountLocked` and mailing the owner twice; a failure could also write a stale counter back over a concurrent one, so the lockout counted too few failures or re-locked after a single failure once a lock expired.
- `attempts_left` on a failed code check (re-authentication) could be too high when another guess ran concurrently, and the exhausted code was not invalidated straight away.
- With `activity.store_identifier = hash`, the same address typed with a decomposed accent produced a different hash; it is now NFC-composed first, like the throttle keys.

### Security

- A locked account's password login now answers exactly like a wrong password (`invalid_credentials`, 422) instead of `too_many_attempts` with the lock's `Retry-After`. Previously anyone could tell an existing account from an unknown address by failing `lockout.threshold` times, and requests against a locked account were never throttled, so one IP could force unlimited password hashing. The attempt now counts against the login throttle like any other guess; the owner still gets the `AccountLockedNotification`. Upgrade: a client that showed a lock countdown from that 429 now shows its usual wrong-credentials message.

## 1.0.2 - 2026-10-04

### Fixed

- Notification emails now say "1 minute" instead of "1 minutes" in the link and code expiry line, with the correct Slovak plural forms; published `notifications.expiry` overrides without plural forms keep working.
- The suspicious-activity email (`SuspiciousSessionNotification`) now describes the reason in the recipient's language — Slovak mail no longer contains English reason text such as `refresh_token_reuse` or `blocked sign-in`. The machine-readable `reason` value in the notification data is unchanged; the wording lives in `notifications.refresh_token_reuse.reasons.*`.

## 1.0.1 - 2026-10-04

### Changed

- Maintenance: `composer.json` `homepage` and `support.docs` now point to the documentation site.

### Fixed

- Slovak (`sk`) translations now ship alongside English for every language file.

## 1.0.0 - 2026-10-03

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
- A typo in a guard switch (`disabled`, `maybe`) — or in `identifier.normalize` /
  `risk.deny_response` — no longer reads as the default: the guard fails to resolve with
  `AuthenticationMisconfigured` naming the full key, and `authentication:check` lists it.
