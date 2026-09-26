# Changelog

All notable changes to `auth-for-laravel` will be documented in this file.

## Unreleased

### Added

- Multi-guard configuration (`authentication.defaults` + per-guard overrides, lists replace)
  with validation at resolution and the `authentication:check` doctor.
- Password, magic-link, email-code and passwordless passkey login.
- The login challenge engine: TOTP / recovery-code and passkey second factors, forced TOTP and
  passkey enrolment, device binding, attempt limits, supersession and single-use finalization.
- Access tokens (jwt-for-laravel, per-guard audience, `sid` / `amr` / `auth_time`) and rotating
  refresh tokens with device sessions; logout current / one / others / everywhere; the
  invalidation policy with re-issued pairs for the acting device.
- Registration (open / invite-only / closed) and invitations; email verification (link or code)
  and verified email change; forgot / reset / change / set password with a policy and an
  optional k-anonymity breached-password check.
- Re-authentication ("sudo mode") with the strength rule for accounts with a second factor.
- Login activity, throttling, opt-in lockout, new-device detection and risk hooks.
- 42 events, 18 localizable notifications (after-response or encrypted-queue delivery),
  opt-in JSON routes, six middleware, five commands and host testing helpers.

### Changed

- `registration.mode = closed` now also refuses accepting invitations (`registration_closed`);
  use `invite_only` for invitation-only sign-up. The doctor warns about `closed` with
  invitations enabled.
- `acceptInvitation()` / `AcceptInvitation` return a `RegistrationResult` like `register()`:
  `verification_required` / `accepted` instead of an error once the account exists.
- `UpdateLocale::execute()` takes a `LocaleData`; `PATCH locale` changes only the fields sent.
- `assertTokensInvalidated()` compares against the version at `actingAsAccount()` (or `since:`)
  and asserts no movement for a `none` scope.
- Typos in `invalidation.*`, `risk.reactions.*`, `reauthentication.methods` /
  `.required_for` and class-string leaves (`registration.rules` / `.creator`, `risk.assessor`,
  `tokens.claims_resolver`, `notifications.classes.*`, `resources.account`) fail guard
  resolution instead of failing mid-flow or silently switching a gate off.
- Requires `symfony/polyfill-intl-normalizer` (emails are compared Unicode-composed, NFC).

### Fixed

- A forced TOTP / passkey enrolment step whose factor was set up meanwhile ends the challenge
  instead of accepting any code or another passkey; the enrolment gate is re-checked on
  completion.
- `POST two-factor/confirm` refuses (`invalid_code`) when TOTP is already on; recovery-code
  regeneration and disabling refuse (`two_factor_not_enabled`, 409) when it is off.
- Throttles count an attempt atomically before the password or code is checked, so concurrent
  guesses cannot all pass the limit.
- A refresh that loses a race to reuse detection or a revoke answers `refresh_invalid` (401)
  and denies the access token it minted, instead of a 500.
- A session without a recorded `auth_time` falls back to its start, never to "now".
- A recovery code used to re-authenticate is announced (`RecoveryCodeUsed` + mail) and recorded
  as such in the marker.
- Guard contexts, `IssueTokenPair` and `InvalidateAccountTokens` refuse an account of another
  guard's model.
- Guard resolution requires the jwt guard's `check_denylist`, and reports why jwt cannot build
  the guard (e.g. an uncallable `token_version`).
- Pending email-change links die with every invalidation; a disabled account cannot confirm one.
- Only completed logins (rows with a session) make a device known for new-device alerts.
- Enumeration-safe registration hashes the password for a taken address too (timing parity).
- `HasAuthentication` routes mail to the guard's `identifier.email_column`.
- The signed-in `POST email/verification` applies the address budget and the resend cooldown.
- `authentication:guard` adds `HasUuids` / `HasUlids` for uuid / ulid keys and prints the
  two-factor / passkey `off` switches it left out.
- `authentication:check` finds routes loaded from the route cache, reads the lower packages'
  configured column names (and the replay-guard column), and judges every run on its own.
- Host registration rules with dotted / wildcard keys keep their validated nested values.
- An invitation's locale must be one of `locale.supported`.
- The manager and the access-token revoker resolve the active container per call (Octane).
- `after_response` notifications are sent inline inside queue workers.
- Events carrying a model serialize it by identifier (`SerializesModels`) for queued listeners.
- A blanked `notifications.urls.confirm_email_change` falls back to the shipped path.
- README: strict-types-safe snippets; the breached-password `fail_closed` answer is a 422
  validation error on `password`.
