# Secure Ticket Vault - WHMCS Addon Module

Lets both staff and clients attach sensitive data (logins, credentials,
API keys, secure notes) to a specific support ticket - including a brand
new ticket that hasn't been submitted yet. Every entry has two fields:
**Label** (what it's for) and **Values** (a free-form, multi-line box for
one or several related values, e.g. "Username: admin / Password: ... /
URL: ..."). Everything is encrypted at rest and **permanently deleted the
moment the ticket's status changes to Closed**.

Confirmed against the current WHMCS release line (9.0.x, PHP 8.2+). The
module only uses documented hooks and the standard `Capsule` database
layer, none of which were touched by the Smarty `{php}`-tag removal in 9.0.

## What it does

- **Admin area**: a native "Add Sensitive Data" button integrated dynamically into the ticket reply box toolbar (with a fallback button at the top of the page if the toolbar isn't found). This allows staff to access the vault without leaving the reply field.
- **Client area, existing ticket**: a floating "🔒 Secure Vault" button in
  the bottom-right corner of `viewticket.php`. This is deliberately *not*
  injected into the page's existing layout - earlier versions tried that
  and it silently failed to appear on real installs because it depended on
  CSS class names that vary by theme/version. A fixed, self-contained
  button avoids that entirely.
- **Client area, new ticket**: the same floating button also appears on
  `submitticket.php`. Since the ticket doesn't exist yet, anything added
  there is "staged" in the browser (via `sessionStorage`, so it survives
  the department-selection step) and is automatically attached to the
  ticket the moment it's created, via the `TicketOpen` hook.
- Values are only decrypted on click ("reveal") - never dumped into the
  page HTML up front.
- Deletion is triggered by `TicketStatusChange` / `TicketClose` /
  `TicketDelete`, plus a daily `DailyCronJob` sweep as a safety net for any
  status change that happens through an unusual code path.

## Installation

1. Copy the `modules/addons/securevault/` folder into your WHMCS
   installation's `modules/addons/` directory.
2. In the admin area, go to **Setup > Addon Modules**, find "Secure Ticket
   Vault," click **Activate**. This creates two tables
   (`mod_securevault_entries`, `mod_securevault_settings`) and generates a
   random 256-bit encryption key stored in the settings table.
3. Under **Setup > Addon Modules > Secure Ticket Vault**, grant access to
   the admin roles that should see it.
4. Open any ticket in the admin area - you'll see the banner at the top.
5. Log in as that client and open the same ticket, or start a brand new
   one - you'll see the floating button in the bottom-right corner.

No template edits are required for either area.

## Known limitations / things worth knowing

- **If you tested an earlier version of this module**: entries added by
  clients before this fix were saved under the wrong ticket reference (see
  the "Client tid vs internal id" note below) and will never show up
  correctly on the admin side. Use the "Purge ALL vault entries now" button
  on **Setup > Addon Modules > Secure Ticket Vault** to clear them out
  before testing again.
- The "staged" entries on the new-ticket page live in the browser only
  until the ticket is actually submitted. If the client closes the tab
  before submitting, those staged entries are lost (nothing was ever sent
  to the server, by design - there's no ticket for them to belong to yet).
- If your ticket submission form's message field isn't named `message`
  (the WHMCS default across all current themes), the auto-attach-on-submit
  listener in `Vault::renderClientWidgetLoader()` won't find the form to
  attach to. Check the `form.querySelector('textarea[name="message"]')`
  line in `lib/Vault.php` if you've heavily customized the order form
  template.
- Admins opening a *new* ticket on a client's behalf (Support > Open
  Ticket in the admin area) don't get the floating button/staging flow -
  only the client-area new-ticket page does. The `TicketOpenAdmin` hook is
  wired up as a no-op-safe hook in case you want to extend this yourself.

## Security notes (please read before using this with real credentials)

- **This is a starting point, not an audited product.** Review it (or have
  someone review it) before storing anything genuinely sensitive.
- The encryption key lives in the database (`mod_securevault_settings`).
  This protects data against things like a leaked backup file, but not
  against someone with full live DB + app access - that's an inherent
  limit of "the app can decrypt it on demand." For stronger isolation,
  move the key to an environment variable or secrets manager instead.
- Enforce HTTPS site-wide - values travel to `ajax.php` in plaintext over
  the wire (protected only by TLS) on add/reveal.
- `ajax.php` checks WHMCS's own session variables (`$_SESSION['adminid']` /
  `$_SESSION['uid']`). For clients, it verifies the ticket's `userid` matches
  the logged-in client. For administrators, it enforces support department-level
  access permission checks (preventing staff from accessing vault data of tickets
  in departments they are not assigned to).
- CSRF validation is enforced on all state-changing requests (`add`, `delete`)
  using WHMCS's native `\WHMCS\Session\Token::validate` helper.
- "Deleted" means a SQL `DELETE` - it's gone. There's also a manual "Purge
  ALL vault entries now" button on **Setup > Addon Modules > Secure Ticket
  Vault** if you ever need to wipe everything immediately.
- Reopening a previously-closed ticket does **not** restore old entries -
  by the time that's possible, they're already gone. Intentional.

### How the client widget finds the right ticket

Earlier versions of this module tried to work out the ticket reference from
the browser's URL (`viewticket.php?tid=X&c=Y`), which breaks if a site has
**Friendly URLs** enabled (no querystring to read on the client side then).
A version after that split detection across two separate hooks
(`ClientAreaPageViewTicket` to resolve the id, `ClientAreaFooterOutput` to
render it) - which turned out to have its own problem: WHMCS doesn't
guarantee those two hooks fire in that order within the same request, so
depending on your WHMCS version/theme the widget could silently render
nothing.

This version does everything in a single hook call
(`ClientAreaFooterOutput`), with no dependency on any other hook having run
first:

1. It checks `basename($_SERVER['SCRIPT_NAME'])` server-side to tell
   `viewticket.php` (existing ticket) apart from `submitticket.php` (new
   ticket) apart from every other page (nothing rendered). This is
   unaffected by Friendly URLs, since the rewrite still ultimately invokes
   the real PHP script - only the browser's address bar looks different.
2. On `viewticket.php`, it reads `tid`/`c` from whatever WHMCS already
   passed into the hook as template variables, falling back to `$_GET` if
   not present - both of which reflect the *real* querystring PHP received,
   even under a Friendly URLs rewrite (again, only the visible URL differs).
3. It resolves those into the real internal `tbltickets.id` the same way
   WHMCS's own `viewticket.php` does, and bakes that id directly into the
   widget's JS as a literal value.
4. `ajax.php` still independently re-verifies that the resolved ticket
   belongs to the logged-in client before allowing anything - the
   client-supplied id is never trusted on its own.

If the widget still doesn't appear, the most likely explanation is a
heavily customized client area that renders ticket pages through something
other than WHMCS's standard `viewticket.php`/`submitticket.php` controllers
(a custom support module, for instance) - in which case `SCRIPT_NAME` won't
match either check. Confirm which script actually handles your ticket
pages and update the `basename(...)` comparison in
`Vault::renderClientWidgetLoader()` accordingly.

## Files

```
modules/addons/securevault/
├── securevault.php   # addon config, activate/deactivate, admin config page
├── hooks.php          # UI injection, new-ticket staging pickup, auto-purge wiring
├── ajax.php           # auth-checked endpoint used by both admin & client widgets
└── lib/
    └── Vault.php       # encryption, CRUD, and widget HTML/JS rendering
```

