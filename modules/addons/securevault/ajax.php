<?php
/**
 * Secure Ticket Vault - ajax.php
 *
 * Called from both the admin-area and client-area widgets. Access control:
 *   - Admin: any logged-in admin staff member (session adminid) can act on
 *     any ticket, same as native WHMCS ticket access.
 *   - Client: must be logged in, and the ticket must belong to their
 *     account (checked via GetTicket API against session uid).
 *
 * All responses are JSON: {"success": bool, ...}
 */

// Bootstrap WHMCS. Path is: modules/addons/securevault/ajax.php -> root/init.php
require_once __DIR__ . '/../../../init.php';
require_once __DIR__ . '/lib/Vault.php';

use SecureVault\Vault;
use WHMCS\Database\Capsule;

header('Content-Type: application/json');

function sv_respond($data)
{
    echo json_encode($data);
    exit;
}

$action = $_POST['action'] ?? '';

// ---------------------------------------------------------------
// Determine caller identity
// ---------------------------------------------------------------

$isAdmin = isset($_SESSION['adminid']) && (int) $_SESSION['adminid'] > 0;
$isClient = !$isAdmin && isset($_SESSION['uid']) && (int) $_SESSION['uid'] > 0;

if (!$isAdmin && !$isClient) {
    sv_respond(['success' => false, 'message' => 'Not authenticated.']);
}

$callerType = $isAdmin ? 'admin' : 'client';
$callerId = $isAdmin ? (int) $_SESSION['adminid'] : (int) $_SESSION['uid'];
$callerName = null;

if ($isAdmin) {
    $admin = Capsule::table('tbladmins')->where('id', $callerId)->first();
    $callerName = $admin ? trim($admin->firstname . ' ' . $admin->lastname) : 'Staff';
} else {
    $client = Capsule::table('tblclients')->where('id', $callerId)->first();
    $callerName = $client ? trim($client->firstname . ' ' . $client->lastname) : 'Client';
}

// ---------------------------------------------------------------
// Resolve the ticket id. Both the admin and client widgets now send the
// real internal id (tbltickets.id) directly - the client widget's copy of
// it was itself resolved server-side, in hooks.php, from the ticket's
// tid+c via the ClientAreaPageViewTicket hook, rather than trusted from
// anything parsed out of the browser URL. We still never trust this value
// blindly: the ownership check right below is the actual security
// boundary, since a client could in principle tamper with the posted
// value in devtools.
// ---------------------------------------------------------------

$ticketId = isset($_POST['ticketid']) ? (int) $_POST['ticketid'] : 0;

// ---------------------------------------------------------------
// Authorization: for clients, verify the ticket actually belongs to them.
// For admins, WHMCS's own admin-area access control already gated the
// page this widget is embedded on.
// ---------------------------------------------------------------

function sv_client_owns_ticket($ticketId, $clientId)
{
    $ticket = Capsule::table('tbltickets')->where('id', $ticketId)->first();
    if (!$ticket) {
        return false;
    }
    // tbltickets.userid = 0 for tickets opened by non-clients/guests.
    return (int) $ticket->userid === (int) $clientId;
}

function sv_admin_has_ticket_access($ticketId, $adminId)
{
    $ticket = Capsule::table('tbltickets')->where('id', $ticketId)->first();
    if (!$ticket) {
        return false;
    }
    $admin = Capsule::table('tbladmins')->where('id', $adminId)->first();
    if (!$admin) {
        return false;
    }
    
    // In WHMCS, supportdepts contains a comma-separated list of department IDs
    $assignedDepts = array_filter(array_map('trim', explode(',', $admin->supportdepts)));
    return in_array((string) $ticket->deptid, $assignedDepts, true);
}

if (!$ticketId && $action !== 'reveal' && $action !== 'delete') {
    sv_respond(['success' => false, 'message' => 'Missing or invalid ticket reference.']);
}

if ($ticketId) {
    if ($isClient && !sv_client_owns_ticket($ticketId, $callerId)) {
        sv_respond(['success' => false, 'message' => 'Not authorized for this ticket.']);
    }
    if ($isAdmin && !sv_admin_has_ticket_access($ticketId, $callerId)) {
        sv_respond(['success' => false, 'message' => 'Not authorized for this ticket.']);
    }
}

// For reveal/delete, resolve the ticket from the entry itself, then re-check
// client and admin ownership/permissions.
if (in_array($action, ['reveal', 'delete'], true)) {
    $entryId = (int) ($_POST['id'] ?? 0);
    $entryTicketId = Vault::getTicketIdForEntry($entryId);

    if (!$entryTicketId) {
        sv_respond(['success' => false, 'message' => 'Entry not found.']);
    }
    if ($isClient && !sv_client_owns_ticket($entryTicketId, $callerId)) {
        sv_respond(['success' => false, 'message' => 'Not authorized for this entry.']);
    }
    if ($isAdmin && !sv_admin_has_ticket_access($entryTicketId, $callerId)) {
        sv_respond(['success' => false, 'message' => 'Not authorized for this entry.']);
    }
}

// CSRF validation for state-changing actions
if (in_array($action, ['add', 'delete'], true)) {
    $token = $_POST['token'] ?? '';
    if (class_exists('\WHMCS\Session\Token') && !\WHMCS\Session\Token::validate($token)) {
        sv_respond(['success' => false, 'message' => 'CSRF verification failed.']);
    }
}

// ---------------------------------------------------------------
// Actions
// ---------------------------------------------------------------

switch ($action) {

    case 'list':
        $entries = Vault::listEntries($ticketId);
        sv_respond([
            'success' => true,
            'entries' => array_map(function ($e) {
                return [
                    'id' => $e->id,
                    'label' => $e->label,
                    'entry_type' => $e->entry_type,
                    'added_by_type' => $e->added_by_type,
                    'added_by_name' => $e->added_by_name,
                ];
            }, $entries->all()),
        ]);
        break;

    case 'add':
        $label = $_POST['label'] ?? '';
        $value = $_POST['value'] ?? '';

        try {
            Vault::addEntry($ticketId, $label, $value, $callerType, $callerId, $callerName);
            sv_respond(['success' => true]);
        } catch (\InvalidArgumentException $e) {
            sv_respond(['success' => false, 'message' => $e->getMessage()]);
        } catch (\Exception $e) {
            sv_respond(['success' => false, 'message' => 'Failed to save entry.']);
        }
        break;

    case 'reveal':
        $entryId = (int) ($_POST['id'] ?? 0);
        $data = Vault::revealEntry($entryId);
        if (!$data) {
            sv_respond(['success' => false, 'message' => 'Entry not found.']);
        }
        if ($data['value'] === null) {
            sv_respond(['success' => false, 'message' => 'Decryption failed.']);
        }
        sv_respond(['success' => true, 'value' => $data['value']]);
        break;

    case 'delete':
        $entryId = (int) ($_POST['id'] ?? 0);
        Vault::deleteEntry($entryId);
        sv_respond(['success' => true]);
        break;

    default:
        sv_respond(['success' => false, 'message' => 'Unknown action.']);
}
