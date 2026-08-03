<?php
/**
 * Secure Ticket Vault - hooks.php
 * WHMCS automatically loads hooks.php from an active addon module's
 * directory, so no manual copy into includes/hooks/ is required.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/lib/Vault.php';

use SecureVault\Vault;
use WHMCS\Database\Capsule;

// -----------------------------------------------------------------
// UI injection
// -----------------------------------------------------------------

// Admin area: banner shown at the top of the View Ticket page.
add_hook('AdminAreaViewTicketPage', 1, function ($vars) {
    if (empty($vars['ticketid'])) {
        return '';
    }
    return Vault::renderAdminWidget($vars['ticketid']);
});

// Client area: renders the floating button + modal. This single hook runs
// on every client area page and does all its own detection server-side -
// it does NOT depend on any other hook having fired first (an earlier
// version tried splitting detection across ClientAreaPageViewTicket +
// ClientAreaFooterOutput and relied on them firing in that order within
// the same request, which WHMCS does not actually guarantee).

// Capture smarty template variables for loader
add_hook('ClientAreaPage', 1, function ($vars) {
    Vault::storeClientPageVars($vars);
    return [];
});

// Output loader wired to all client output hooks to ensure compatibility
// with custom themes that may omit {$footeroutput} or {$headoutput} in templates.
add_hook('ClientAreaHeaderOutput', 1, function ($vars) {
    return Vault::renderClientWidgetLoader($vars);
});
add_hook('ClientAreaHeadOutput', 1, function ($vars) {
    return Vault::renderClientWidgetLoader($vars);
});
add_hook('ClientAreaFooterOutput', 1, function ($vars) {
    return Vault::renderClientWidgetLoader($vars);
});

// -----------------------------------------------------------------
// New-ticket staging: a client can add vault entries on the "open a
// new ticket" page before the ticket exists yet. Those get posted
// alongside the ticket submission as a hidden field, and picked up
// here once WHMCS has actually created the ticket.
// -----------------------------------------------------------------

add_hook('TicketOpen', 1, function ($vars) {
    if (empty($vars['ticketid'])) {
        return;
    }
    $ticket = Capsule::table('tbltickets')->where('id', $vars['ticketid'])->first();
    $clientId = $ticket ? (int) $ticket->userid : null;
    $clientName = null;
    if ($clientId) {
        $client = Capsule::table('tblclients')->where('id', $clientId)->first();
        $clientName = $client ? trim($client->firstname . ' ' . $client->lastname) : null;
    }
    Vault::consumePendingFromRequest($vars['ticketid'], 'client', $clientId, $clientName);
});

add_hook('TicketOpenAdmin', 1, function ($vars) {
    // Covers tickets an admin opens on behalf of a client, in case the
    // same staging mechanism is ever wired into an admin-side "open new
    // ticket" form. Safe no-op if no pending field was sent.
    if (empty($vars['ticketid'])) {
        return;
    }
    Vault::consumePendingFromRequest($vars['ticketid'], 'admin', $_SESSION['adminid'] ?? null, null);
});

// -----------------------------------------------------------------
// Auto-purge triggers
// -----------------------------------------------------------------

add_hook('TicketStatusChange', 1, function ($vars) {
    Vault::purgeIfClosed($vars);
});

add_hook('TicketClose', 1, function ($vars) {
    if (!empty($vars['ticketid'])) {
        Vault::purgeByTicketId($vars['ticketid']);
    }
});

add_hook('TicketDelete', 1, function ($vars) {
    if (!empty($vars['ticketid'])) {
        Vault::purgeByTicketId($vars['ticketid']);
    }
});

// Safety-net sweep in case a status change ever happens through a code path
// that doesn't fire the hooks above (e.g. a direct DB update by another
// module). Runs once daily alongside the rest of WHMCS's cron tasks.
add_hook('DailyCronJob', 1, function ($vars) {
    Vault::purgeOrphanedAndClosed();
});
