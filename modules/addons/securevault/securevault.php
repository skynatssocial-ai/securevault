<?php
/**
 * Secure Ticket Vault - WHMCS Addon Module
 *
 * Lets admins and clients attach sensitive data (logins, passwords, etc.)
 * to a specific support ticket. All values are encrypted at rest and are
 * permanently deleted the moment the ticket's status changes to Closed.
 *
 * IMPORTANT: Review the security notes in README.md before using this in
 * production. Encrypted-at-rest is not the same as "safe to store forever" -
 * the whole point of this module is that data does NOT live forever.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;

require_once __DIR__ . '/lib/Vault.php';

function securevault_config()
{
    return [
        'name' => 'Secure Ticket Vault',
        'description' => 'Encrypted, ticket-scoped storage for sensitive data (logins, credentials, etc.) shared between staff and clients. Entries are permanently deleted when the ticket is closed.',
        'version' => '1.0.0',
        'author' => 'Custom',
        'fields' => [
            'info' => [
                'FriendlyName' => 'How this works',
                'Type' => 'text',
                'Description' => 'A "Secure Vault" panel is added to every ticket, in both the admin area and the client area. Anything stored there is encrypted in the database and is deleted the instant the ticket status becomes Closed (plus a daily safety-net sweep). There is no way to recover data after a ticket closes - this is by design.',
            ],
        ],
    ];
}

function securevault_activate()
{
    try {
        if (!Capsule::schema()->hasTable('mod_securevault_entries')) {
            Capsule::schema()->create('mod_securevault_entries', function ($table) {
                $table->increments('id');
                $table->integer('ticket_id')->index();
                $table->string('label', 191);
                $table->string('entry_type', 50)->default('other');
                $table->text('value_encrypted');
                $table->enum('added_by_type', ['client', 'admin']);
                $table->integer('added_by_id')->nullable();
                $table->string('added_by_name', 191)->nullable();
                $table->timestamp('created_at')->useCurrent();
            });
        }

        if (!Capsule::schema()->hasTable('mod_securevault_settings')) {
            Capsule::schema()->create('mod_securevault_settings', function ($table) {
                $table->string('setting', 100)->primary();
                $table->text('value')->nullable();
            });
        }

        // Generate a per-install encryption key once, store it outside the
        // normal addon config screen (so it isn't casually visible/editable
        // in Setup > Addon Modules).
        $existing = Capsule::table('mod_securevault_settings')->where('setting', 'encryption_key')->first();
        if (!$existing) {
            Capsule::table('mod_securevault_settings')->insert([
                'setting' => 'encryption_key',
                'value' => bin2hex(random_bytes(32)),
            ]);
        }

        return [
            'status' => 'success',
            'description' => 'Secure Ticket Vault installed. See README.md for the manual step required (adding the addon\'s hooks.php is automatic, but double check file permissions on the module directory).',
        ];
    } catch (\Exception $e) {
        return [
            'status' => 'error',
            'description' => 'Activation failed: ' . $e->getMessage(),
        ];
    }
}

function securevault_deactivate()
{
    // Deliberately does NOT drop tables or wipe data on deactivate - only on
    // explicit "Uninstall/Remove Module Files" from WHMCS, and even then we
    // leave the DB tables in place so an admin can't lose data by accident.
    // Since entries auto-purge on ticket close, anything left is almost
    // always tied to still-open tickets.
    return [
        'status' => 'success',
        'description' => 'Secure Ticket Vault deactivated. Existing encrypted entries were left in place. Drop the mod_securevault_entries / mod_securevault_settings tables manually if you want a full wipe.',
    ];
}

/**
 * Admin config page - Addon Modules > Secure Ticket Vault
 * Shows basic stats and a manual "purge all" panic button.
 */
function securevault_output($vars)
{
    $modulelink = $vars['modulelink'];

    if (isset($_POST['securevault_purge_all']) && $_POST['securevault_purge_all'] === '1') {
        Capsule::table('mod_securevault_entries')->truncate();
        echo '<div class="alert alert-success">All stored vault entries have been permanently deleted.</div>';
    }

    $totalEntries = Capsule::table('mod_securevault_entries')->count();
    $ticketsWithEntries = Capsule::table('mod_securevault_entries')->distinct()->count('ticket_id');

    echo '<h3>Secure Ticket Vault</h3>';
    echo '<p>Currently storing <strong>' . (int) $totalEntries . '</strong> encrypted entr' . ($totalEntries == 1 ? 'y' : 'ies') . ' across <strong>' . (int) $ticketsWithEntries . '</strong> ticket(s). Entries for a ticket are deleted automatically the moment that ticket is closed.</p>';
    echo '<form method="post" onsubmit="return confirm(\'This will immediately and permanently delete ALL stored vault entries for ALL tickets, including open ones. This cannot be undone. Continue?\');">';
    echo '<input type="hidden" name="securevault_purge_all" value="1">';
    echo '<button type="submit" class="btn btn-danger btn-sm">Purge ALL vault entries now</button>';
    echo '</form>';
}
