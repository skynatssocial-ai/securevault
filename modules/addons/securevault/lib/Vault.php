<?php

namespace SecureVault;

use WHMCS\Database\Capsule;
use WHMCS\Config\Setting;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

class Vault
{
    protected static $keyCache = null;

    // ---------------------------------------------------------------
    // Encryption
    // ---------------------------------------------------------------

    protected static function getKey()
    {
        if (self::$keyCache !== null) {
            return self::$keyCache;
        }

        $row = Capsule::table('mod_securevault_settings')->where('setting', 'encryption_key')->first();

        if (!$row || empty($row->value)) {
            throw new \RuntimeException('Secure Vault encryption key is missing. Reactivate the Secure Ticket Vault addon module.');
        }

        self::$keyCache = hex2bin($row->value);
        return self::$keyCache;
    }

    protected static function encrypt($plaintext)
    {
        $key = self::getKey();
        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($cipher === false) {
            throw new \RuntimeException('Encryption failed.');
        }
        return base64_encode($iv . $tag . $cipher);
    }

    protected static function decrypt($encoded)
    {
        $key = self::getKey();
        $raw = base64_decode($encoded);
        if ($raw === false || strlen($raw) < 28) {
            return null;
        }
        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $cipher = substr($raw, 28);
        $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return $plain === false ? null : $plain;
    }

    // ---------------------------------------------------------------
    // CRUD
    // ---------------------------------------------------------------

    /**
     * @param int    $ticketId
     * @param string $label     What the value(s) are for, e.g. "cPanel login"
     * @param string $value     Free-form, can be multi-line ("Username: ...\nPassword: ...")
     * @param string $byType    'client' or 'admin'
     * @param int|null $byId
     * @param string|null $byName
     */
    public static function addEntry($ticketId, $label, $value, $byType, $byId, $byName)
    {
        $label = trim((string) $label);
        $value = trim((string) $value);

        if ($label === '' || $value === '') {
            throw new \InvalidArgumentException('Label and value are both required.');
        }

        return Capsule::table('mod_securevault_entries')->insertGetId([
            'ticket_id'       => (int) $ticketId,
            'label'           => $label,
            'entry_type'      => 'note',
            'value_encrypted' => self::encrypt($value),
            'added_by_type'   => $byType === 'client' ? 'client' : 'admin',
            'added_by_id'     => $byId !== null ? (int) $byId : null,
            'added_by_name'   => $byName,
            'created_at'      => date('Y-m-d H:i:s'),
        ]);
    }

    /**
     * Returns entry metadata only (no decrypted values) for listing.
     */
    public static function listEntries($ticketId)
    {
        return Capsule::table('mod_securevault_entries')
            ->where('ticket_id', (int) $ticketId)
            ->orderBy('created_at', 'asc')
            ->get();
    }

    /**
     * Decrypts a single entry's value on demand. Caller must verify the
     * entry belongs to a ticket the requester is allowed to view before
     * calling this.
     */
    public static function revealEntry($entryId)
    {
        $row = Capsule::table('mod_securevault_entries')->where('id', (int) $entryId)->first();
        if (!$row) {
            return null;
        }
        return [
            'label' => $row->label,
            'value' => self::decrypt($row->value_encrypted),
        ];
    }

    public static function getTicketIdForEntry($entryId)
    {
        $row = Capsule::table('mod_securevault_entries')->where('id', (int) $entryId)->first();
        return $row ? (int) $row->ticket_id : null;
    }

    public static function deleteEntry($entryId)
    {
        return Capsule::table('mod_securevault_entries')->where('id', (int) $entryId)->delete();
    }

    public static function purgeByTicketId($ticketId)
    {
        return Capsule::table('mod_securevault_entries')->where('ticket_id', (int) $ticketId)->delete();
    }

    // ---------------------------------------------------------------
    // Hook-driven purge logic
    // ---------------------------------------------------------------

    public static function purgeIfClosed($vars)
    {
        $ticketId = $vars['ticketid'] ?? $vars['id'] ?? null;
        $status = $vars['status'] ?? '';

        if ($ticketId && strtolower((string) $status) === 'closed') {
            self::purgeByTicketId($ticketId);
        }
    }

    /**
     * Safety-net sweep, run from DailyCronJob. Catches any ticket that is
     * Closed but still has stray entries, and cleans up entries whose
     * ticket no longer exists at all.
     */
    public static function purgeOrphanedAndClosed()
    {
        Capsule::table('mod_securevault_entries')
            ->whereNotIn('ticket_id', function ($query) {
                $query->select('id')->from('tbltickets');
            })
            ->orWhereIn('ticket_id', function ($query) {
                $query->select('id')->from('tbltickets')->where('status', 'Closed');
            })
            ->delete();
    }

    /**
     * Called from TicketOpen (client-submitted) / TicketOpenAdmin
     * (admin-submitted on behalf of a client). Reads any staged entries the
     * client added on the "new ticket" page before the ticket existed, and
     * attaches them to the just-created ticket.
     */
    public static function consumePendingFromRequest($ticketId, $byType, $byId, $byName)
    {
        $raw = $_POST['securevault_pending'] ?? '';
        if ($raw === '') {
            return;
        }

        $items = json_decode($raw, true);
        if (!is_array($items)) {
            return;
        }

        foreach ($items as $item) {
            $label = $item['label'] ?? '';
            $value = $item['value'] ?? '';
            if ($label === '' || $value === '') {
                continue;
            }
            try {
                self::addEntry($ticketId, $label, $value, $byType, $byId, $byName);
            } catch (\Exception $e) {
                // Skip malformed entries rather than blocking ticket creation.
                continue;
            }
        }
    }

    // ---------------------------------------------------------------
    // Widget rendering
    // ---------------------------------------------------------------

    protected static function ajaxUrl()
    {
        $base = rtrim(Setting::getValue('SystemURL'), '/');
        return $base . '/modules/addons/securevault/ajax.php';
    }

    protected static function sharedStyles()
    {
        return <<<CSS
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');
        
        .sv-fab {
            position: fixed; z-index: 99998; right: 24px; bottom: 24px;
            background: linear-gradient(135deg, #e11d48 0%, #be123c 100%);
            color: #fff; border: none; border-radius: 999px;
            padding: 12px 24px; font-size: 14px; font-weight: 600; cursor: pointer;
            box-shadow: 0 10px 15px -3px rgba(225, 29, 72, 0.3), 0 4px 6px -4px rgba(225, 29, 72, 0.3);
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex; align-items: center; gap: 8px;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .sv-fab:hover {
            transform: translateY(-2px);
            box-shadow: 0 20px 25px -5px rgba(225, 29, 72, 0.4), 0 8px 10px -6px rgba(225, 29, 72, 0.4);
            background: linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);
        }
        .sv-fab:active {
            transform: translateY(0);
        }
        
        .sv-overlay {
            position: fixed; z-index: 99999; inset: 0;
            background: rgba(15, 23, 42, 0.4);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            display: flex; align-items: center; justify-content: center;
            opacity: 0; pointer-events: none;
            transition: opacity 0.25s ease-out;
        }
        .sv-overlay.sv-open {
            opacity: 1; pointer-events: auto;
        }
        
        .sv-modal {
            background: #fff; border-radius: 16px; width: 92%; max-width: 600px;
            max-height: 84vh; overflow-y: auto; padding: 24px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            border: 1px solid rgba(226, 232, 240, 0.8);
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            transform: scale(0.95) translateY(10px);
            transition: transform 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        .sv-overlay.sv-open .sv-modal {
            transform: scale(1) translateY(0);
        }
        
        .sv-modal-header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 8px;
        }
        
        .sv-modal h4 {
            margin: 0; font-size: 18px; font-weight: 700; color: #0f172a;
            display: flex; align-items: center; gap: 8px;
        }
        .sv-modal .sv-sub {
            font-size: 13px; color: #64748b; line-height: 1.5; margin-bottom: 20px;
        }
        
        .sv-table-container {
            border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden;
            margin-bottom: 20px; background: #f8fafc;
        }
        
        .sv-modal table {
            width: 100%; font-size: 13px; border-collapse: collapse; margin-bottom: 0;
        }
        .sv-modal th {
            background: #f1f5f9; color: #475569; font-weight: 600;
            padding: 10px 14px; text-align: left; border-bottom: 1px solid #e2e8f0;
        }
        .sv-modal td {
            padding: 12px 14px; text-align: left; vertical-align: middle;
            border-bottom: 1px solid #e2e8f0; background: #fff;
        }
        .sv-modal tr:last-child td {
            border-bottom: none;
        }
        .sv-modal tr:hover td {
            background: #f8fafc;
        }
        
        .sv-modal .sv-value {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            white-space: pre-wrap; word-break: break-all; font-size: 12px;
            color: #0f172a; background: #f1f5f9; padding: 4px 8px; border-radius: 6px;
            display: inline-block; max-width: 260px;
        }
        .sv-modal .sv-masked {
            color: #94a3b8; font-size: 14px; letter-spacing: 2px;
        }
        
        .sv-modal .sv-meta {
            font-size: 11px; font-weight: 500;
        }
        .sv-badge {
            display: inline-block; padding: 2px 8px; border-radius: 999px;
            font-size: 10px; font-weight: 600; text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .sv-badge-admin {
            background: #e0f2fe; color: #0369a1;
        }
        .sv-badge-client {
            background: #dcfce7; color: #15803d;
        }
        .sv-badge-pending {
            background: #fef3c7; color: #b45309;
        }
        
        .sv-form-group {
            display: flex; flex-direction: column; gap: 12px; margin-bottom: 20px;
        }
        
        .sv-modal input, .sv-modal textarea {
            width: 100%; font-size: 13px; padding: 10px 14px; box-sizing: border-box;
            border: 1px solid #cbd5e1; border-radius: 8px; background: #fff;
            color: #0f172a; transition: all 0.2s ease;
            font-family: inherit;
        }
        .sv-modal input:focus, .sv-modal textarea:focus {
            outline: none; border-color: #e11d48;
            box-shadow: 0 0 0 3px rgba(225, 29, 72, 0.15);
            background: #fff;
        }
        .sv-modal textarea {
            min-height: 80px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            resize: vertical;
        }
        
        .sv-modal .sv-actions {
            display: flex; justify-content: flex-end; gap: 10px;
        }
        .sv-modal button.sv-btn {
            font-size: 13px; font-weight: 600; padding: 10px 18px; border-radius: 8px;
            border: 1px solid #cbd5e1; background: #fff; color: #475569;
            cursor: pointer; transition: all 0.2s ease;
            font-family: inherit;
        }
        .sv-modal button.sv-btn:hover {
            background: #f1f5f9; color: #0f172a; border-color: #94a3b8;
        }
        .sv-modal button.sv-btn-primary {
            background: linear-gradient(135deg, #e11d48 0%, #be123c 100%);
            color: #fff; border: none;
            box-shadow: 0 4px 6px -1px rgba(225, 29, 72, 0.2), 0 2px 4px -1px rgba(225, 29, 72, 0.1);
        }
        .sv-modal button.sv-btn-primary:hover {
            background: linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);
            color: #fff; transform: translateY(-1px);
            box-shadow: 0 10px 15px -3px rgba(225, 29, 72, 0.3), 0 4px 6px -4px rgba(225, 29, 72, 0.3);
        }
        .sv-modal button.sv-btn-primary:active {
            transform: translateY(0);
        }
        
        .sv-modal button.sv-close {
            background: #f1f5f9; border: none; font-size: 16px; cursor: pointer;
            line-height: 1; color: #64748b; width: 28px; height: 28px;
            border-radius: 999px; display: flex; align-items: center; justify-content: center;
            transition: all 0.2s ease;
        }
        .sv-modal button.sv-close:hover {
            background: #e2e8f0; color: #0f172a;
        }
        
        .sv-modal .sv-link-btn {
            background: none; border: none; color: #2563eb; cursor: pointer;
            padding: 0; font-size: 12px; font-weight: 600; transition: all 0.15s ease;
        }
        .sv-modal .sv-link-btn:hover {
            color: #1d4ed8; text-decoration: underline;
        }
        .sv-empty {
            font-size: 13px; color: #64748b; text-align: center; padding: 24px;
            background: #fff; border-radius: 12px;
        }
        CSS;
    }

    /**
     * Admin area: banner injected at the top of the View Ticket page via the
     * AdminAreaViewTicketPage hook (which is documented to output HTML
     * directly, so this is reliably visible without any theme editing).
     */
    public static function renderAdminWidget($ticketId)
    {
        $ticketId = (int) $ticketId;
        $ajaxUrl = self::ajaxUrl();
        $uid = 'sv_admin_' . $ticketId;

        return self::renderModalMarkup($uid, 'existing', $ticketId, $ajaxUrl, true);
    }

    /**
     * Client area: injected on every page via ClientAreaFooterOutput.
     * Does its own page detection here, in this single hook call, rather
     * than relying on a different hook (e.g. ClientAreaPageViewTicket)
     * having already run earlier in the same request - WHMCS does not
     * guarantee an order between two independent hook points, so an
     * earlier version of this that split detection across two hooks could
     * silently render nothing depending on that order.
     *
     * Detection uses the server-side script name and $_GET rather than
     * anything from the browser's visible URL, so it keeps working
     * correctly even when Friendly URLs are enabled (the rewrite still
     * passes the real tid/c through to PHP - only the address bar changes).
     */
    public static function renderClientWidgetLoader($vars = [])
    {
        $script = basename((string) ($_SERVER['SCRIPT_NAME'] ?? ''));

        if ($script === 'viewticket.php') {
            // Prefer whatever WHMCS already assigned to the template (passed
            // into this hook as $vars, since ClientAreaFooterOutput receives
            // "all currently defined template variables"); fall back to the
            // raw querystring, which PHP sees correctly even under a
            // Friendly URLs rewrite.
            $tid = $vars['tid'] ?? ($_GET['tid'] ?? null);
            $c = $vars['c'] ?? ($_GET['c'] ?? null);

            if ($tid === null || $c === null) {
                return '';
            }

            $ticket = Capsule::table('tbltickets')->where('tid', $tid)->where('c', $c)->first();
            if (!$ticket) {
                return '';
            }

            return self::renderClientWidget((int) $ticket->id, false);
        }

        if ($script === 'submitticket.php') {
            return self::renderClientWidget(null, true);
        }

        return '';
    }

    protected static function renderClientWidget($ticketId, $isNewTicketPage)
    {
        $ajaxUrl = self::ajaxUrl();
        $styles = self::sharedStyles();
        $jsonAjaxUrl = json_encode($ajaxUrl);
        $jsonTicketId = json_encode($ticketId ? (int) $ticketId : null);
        $jsonIsNew = json_encode((bool) $isNewTicketPage);
        $csrfToken = '';
        if (class_exists('\WHMCS\Session\Token')) {
            $csrfToken = \WHMCS\Session\Token::get();
        }
        $jsonToken = json_encode($csrfToken);

        return <<<HTML
        <style>{$styles}</style>
        <script>
        (function () {
            var ajaxUrl = {$jsonAjaxUrl};
            // Resolved server-side (see hooks.php) - the real internal
            // ticket id for an existing ticket, or null on the new-ticket
            // page where no ticket exists yet.
            var ticketId = {$jsonTicketId};
            var isNew = {$jsonIsNew};
            var csrfToken = {$jsonToken};
            var STORAGE_KEY = 'securevault_pending_newticket';

            function loadPending() {
                try { return JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '[]'); }
                catch (e) { return []; }
            }
            function savePending(items) {
                try { sessionStorage.setItem(STORAGE_KEY, JSON.stringify(items)); } catch (e) {}
            }

            var pending = isNew ? loadPending() : [];
            if (!isNew) {
                try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) {}
            }

            function esc(s) {
                var d = document.createElement('div');
                d.innerText = s == null ? '' : s;
                return d.innerHTML;
            }

            function post(action, data) {
                data = data || {};
                data.action = action;
                data.token = csrfToken;
                if (ticketId) { data.ticketid = ticketId; }
                var body = Object.keys(data).map(function (k) {
                    return encodeURIComponent(k) + '=' + encodeURIComponent(data[k]);
                }).join('&');
                return fetch(ajaxUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    credentials: 'same-origin',
                    body: body
                }).then(function (r) { return r.json(); });
            }

            // ---- build FAB + modal ----
            var fab = document.createElement('button');
            fab.type = 'button';
            fab.className = 'sv-fab';
            fab.innerText = '🔒 Add Sensitive Data';
            document.body.appendChild(fab);

            var overlay = document.createElement('div');
            overlay.className = 'sv-overlay';
            overlay.innerHTML =
                '<div class="sv-modal">' +
                    '<div class="sv-modal-header">' +
                        '<h4>🔒 Add Sensitive Data</h4>' +
                        '<button type="button" class="sv-close">&times;</button>' +
                    '</div>' +
                    '<div class="sv-sub">' + (isNew
                        ? 'Anything added here will be attached to this ticket once you submit it, and permanently deleted when the ticket is closed.'
                        : 'Everything here is permanently deleted the moment this ticket is closed.') + '</div>' +
                    '<div class="sv-list"></div>' +
                    '<div class="sv-form-group">' +
                        '<input type="text" class="sv-label" placeholder="Label (e.g. cPanel login)">' +
                        '<textarea class="sv-value" placeholder="Value(s) - e.g.\nUsername: admin\nPassword: ...\nURL: ..."></textarea>' +
                    '</div>' +
                    '<div class="sv-actions">' +
                        '<button type="button" class="sv-btn sv-add sv-btn-primary">Add to vault</button>' +
                    '</div>' +
                '</div>';
            document.body.appendChild(overlay);

            var listEl = overlay.querySelector('.sv-list');
            var labelInput = overlay.querySelector('.sv-label');
            var valueInput = overlay.querySelector('.sv-value');

            fab.addEventListener('click', function () {
                overlay.classList.add('sv-open');
                if (!isNew) { load(); } else { renderPending(); }
            });
            overlay.querySelector('.sv-close').addEventListener('click', function () {
                overlay.classList.remove('sv-open');
            });
            overlay.addEventListener('click', function (ev) {
                if (ev.target === overlay) { overlay.classList.remove('sv-open'); }
            });

            function renderRows(rows, opts) {
                if (!rows.length) {
                    listEl.innerHTML = '<div class="sv-empty">No entries yet.</div>';
                    return;
                }
                var html = '<div class="sv-table-container"><table><tr><th>Label</th><th>Values</th><th>Added by</th><th></th></tr>';
                rows.forEach(function (e, idx) {
                    var revealCell = opts.pending
                        ? '<span class="sv-value">' + esc(e.value) + '</span>'
                        : '<span class="sv-masked">\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022</span> <button type="button" class="sv-link-btn sv-reveal">reveal</button>';
                    
                    var badge = '';
                    if (opts.pending) {
                        badge = ' <span class="sv-badge sv-badge-pending">pending</span>';
                    } else if (e.added_by_type === 'admin') {
                        badge = ' <span class="sv-badge sv-badge-admin">staff</span>';
                    } else {
                        badge = ' <span class="sv-badge sv-badge-client">client</span>';
                    }
                    var adderName = esc(opts.pending ? 'you' : (e.added_by_name || e.added_by_type));

                    html += '<tr data-id="' + (opts.pending ? idx : e.id) + '">' +
                        '<td style="font-weight:600;color:#334155;">' + esc(e.label) + '</td>' +
                        '<td class="sv-value-cell">' + revealCell + '</td>' +
                        '<td class="sv-meta">' + adderName + badge + '</td>' +
                        '<td><button type="button" class="sv-link-btn sv-delete" style="color:#ef4444;">remove</button></td>' +
                        '</tr>';
                });
                html += '</table></div>';
                listEl.innerHTML = html;
            }

            function load() {
                listEl.innerHTML = '<div class="sv-empty">Loading...</div>';
                post('list').then(function (res) {
                    if (res.success) { renderRows(res.entries, { pending: false }); }
                    else { listEl.innerHTML = '<div class="sv-empty">' + esc(res.message || 'Failed to load.') + '</div>'; }
                }).catch(function (err) {
                    listEl.innerHTML = '<div class="sv-empty">Connection error or session expired.</div>';
                });
            }

            function renderPending() {
                renderRows(pending, { pending: true });
            }

            listEl.addEventListener('click', function (ev) {
                var row = ev.target.closest('tr');
                if (!row) { return; }
                var id = row.getAttribute('data-id');

                if (ev.target.classList.contains('sv-reveal')) {
                    post('reveal', { id: id }).then(function (res) {
                        if (res.success) {
                            row.querySelector('.sv-value-cell').innerHTML = '<span class="sv-value">' + esc(res.value) + '</span>';
                        } else {
                            alert(res.message || 'Failed to decrypt.');
                        }
                    }).catch(function (err) {
                        alert('Connection error or session expired.');
                    });
                }

                if (ev.target.classList.contains('sv-delete')) {
                    if (!confirm('Remove this entry permanently?')) { return; }
                    if (isNew) {
                        pending.splice(parseInt(id, 10), 1);
                        savePending(pending);
                        renderPending();
                    } else {
                        post('delete', { id: id }).then(function (res) {
                            if (res.success) { row.remove(); }
                            else { alert(res.message || 'Could not delete entry.'); }
                        }).catch(function (err) {
                            alert('Connection error or session expired.');
                        });
                    }
                }
            });

            overlay.querySelector('.sv-add').addEventListener('click', function () {
                var label = labelInput.value.trim();
                var value = valueInput.value.trim();
                if (!label || !value) { alert('Please fill in both the label and the value(s).'); return; }

                if (isNew) {
                    pending.push({ label: label, value: value });
                    savePending(pending);
                    labelInput.value = ''; valueInput.value = '';
                    renderPending();
                } else {
                    post('add', { label: label, value: value }).then(function (res) {
                        if (res.success) {
                            labelInput.value = ''; valueInput.value = '';
                            load();
                        } else {
                            alert(res.message || 'Could not add entry.');
                        }
                    }).catch(function (err) {
                        alert('Connection error or session expired.');
                    });
                }
            });

            // On the new-ticket page, attach staged entries to the actual
            // ticket submission form right before it posts, then clear the
            // staged copy so it isn't reused if the same tab opens another
            // new ticket later.
            if (isNew) {
                document.addEventListener('submit', function (ev) {
                    var form = ev.target;
                    if (!(form instanceof HTMLFormElement)) { return; }
                    if (!form.querySelector('textarea[name="message"]')) { return; }
                    var items = loadPending();
                    if (!items.length) { return; }
                    var hidden = document.createElement('input');
                    hidden.type = 'hidden';
                    hidden.name = 'securevault_pending';
                    hidden.value = JSON.stringify(items);
                    form.appendChild(hidden);
                    // Do not clear sessionStorage immediately to prevent data loss on validation failure.
                }, true);
            }
        })();
        </script>
        HTML;
    }


    /**
     * Shared modal markup used for the admin banner (simple server-rendered
     * version; admin side doesn't need the "new ticket" staging flow since
     * the admin is always looking at a ticket that already exists).
     */
    protected static function renderModalMarkup($uid, $mode, $ticketId, $ajaxUrl, $isAdmin)
    {
        $styles = self::sharedStyles();
        $token = '';
        if (class_exists('\WHMCS\Session\Token')) {
            $token = \WHMCS\Session\Token::get();
        }
        ob_start();
        ?>
        <style><?php echo $styles; ?></style>
        <div id="<?php echo $uid; ?>">
            <button type="button" class="sv-fab" style="position:static;display:none;">Add Sensitive Data</button>
            <div class="sv-overlay">
                <div class="sv-modal">
                    <div class="sv-modal-header">
                        <h4>🔒 Sensitive Data</h4>
                        <button type="button" class="sv-close">&times;</button>
                    </div>
                    <div class="sv-sub">Everything here is permanently deleted the moment this ticket is closed.</div>
                    <div class="sv-list"></div>
                    <div class="sv-form-group">
                        <input type="text" class="sv-label" placeholder="Label (e.g. cPanel login)">
                        <textarea class="sv-value" placeholder="Value(s) - e.g.&#10;Username: admin&#10;Password: ...&#10;URL: ..."></textarea>
                    </div>
                    <div class="sv-actions">
                        <button type="button" class="sv-btn sv-add sv-btn-primary">Add to vault</button>
                    </div>
                </div>
            </div>
        </div>
        <script>
        (function () {
            function init() {
                var root = document.getElementById(<?php echo json_encode($uid); ?>);
                if (!root) { return; }
                var ticketId = <?php echo (int) $ticketId; ?>;
                var ajaxUrl = <?php echo json_encode($ajaxUrl); ?>;
                var csrfToken = <?php echo json_encode($token); ?>;
                var fab = root.querySelector('.sv-fab');
                var overlay = root.querySelector('.sv-overlay');
                var listEl = root.querySelector('.sv-list');
                var labelInput = root.querySelector('.sv-label');
                var valueInput = root.querySelector('.sv-value');

                // Dynanically inject into the WHMCS View Ticket Reply Toolbar
                var btnContainer = null;
                var insertBeforeNode = null;

                // Try to find the Return to Ticket List checkbox/label
                var returnCb = document.querySelector('input[name="return"]') || 
                               document.querySelector('input[name="return_to_list"]') || 
                               document.getElementById('return') ||
                               document.getElementById('cbReturn');
                
                if (returnCb) {
                    // If the checkbox is wrapped in a label or a bootstrap checkbox wrapper
                    if (returnCb.closest('label')) {
                        insertBeforeNode = returnCb.closest('label');
                        btnContainer = insertBeforeNode.parentElement;
                    } else if (returnCb.closest('.checkbox-inline') || returnCb.closest('.checkbox')) {
                        insertBeforeNode = returnCb.closest('.checkbox-inline') || returnCb.closest('.checkbox');
                        btnContainer = insertBeforeNode.parentElement;
                    } else {
                        insertBeforeNode = returnCb;
                        btnContainer = returnCb.parentElement;
                    }
                } else {
                    // Fallback: Try to find the More options button
                    var moreOptions = Array.from(document.querySelectorAll('button, a, input')).find(function (el) {
                        var text = el.innerText || el.value || '';
                        return text.indexOf('More options') !== -1;
                    });
                    if (moreOptions) {
                        var group = moreOptions.closest('.btn-group') || moreOptions;
                        btnContainer = group.parentElement;
                        insertBeforeNode = group.nextSibling;
                    } else {
                        // Fallback: Try to find the Reply submit button
                        var replyBtn = document.querySelector('input[type="submit"][value="Reply"]') || 
                                       document.querySelector('input[type="submit"][value*="Reply"]') ||
                                       Array.from(document.querySelectorAll('button[type="submit"]')).find(function(el) {
                                           return el.innerText.indexOf('Reply') !== -1;
                                       }) ||
                                       Array.from(document.querySelectorAll('input[type="submit"]')).find(function(el) {
                                           return el.value.indexOf('Reply') !== -1;
                                       });
                        if (replyBtn) {
                            btnContainer = replyBtn.parentElement;
                            insertBeforeNode = replyBtn;
                        }
                    }
                }

                if (btnContainer) {
                    fab.className = 'btn btn-danger btn-sm';
                    fab.style.marginRight = '8px';
                    fab.style.marginBottom = '0px';
                    fab.style.display = 'inline-block';
                    fab.style.position = 'static';
                    fab.style.padding = '6px 12px';
                    fab.style.fontSize = '12px';
                    fab.style.fontWeight = 'normal';
                    fab.style.backgroundColor = '#d9534f';
                    fab.style.borderColor = '#d43f3a';
                    fab.innerText = 'Add Sensitive Data';

                    if (insertBeforeNode) {
                        btnContainer.insertBefore(fab, insertBeforeNode);
                    } else {
                        btnContainer.appendChild(fab);
                    }
                } else {
                    // Inline fallback if the reply box toolbar is not found
                    fab.className = 'btn btn-danger btn-sm';
                    fab.style.display = 'inline-block';
                    fab.style.position = 'static';
                    fab.style.marginBottom = '10px';
                    fab.style.backgroundColor = '#d9534f';
                    fab.style.borderColor = '#d43f3a';
                    fab.innerText = 'Add Sensitive Data';
                }

                function esc(s) {
                    var d = document.createElement('div');
                    d.innerText = s == null ? '' : s;
                    return d.innerHTML;
                }
                function post(action, data) {
                    data = data || {};
                    data.action = action;
                    data.token = csrfToken;
                    data.ticketid = ticketId;
                    var body = Object.keys(data).map(function (k) {
                        return encodeURIComponent(k) + '=' + encodeURIComponent(data[k]);
                    }).join('&');
                    return fetch(ajaxUrl, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        credentials: 'same-origin',
                        body: body
                    }).then(function (r) { return r.json(); });
                }
                function render(entries) {
                    if (!entries.length) {
                        listEl.innerHTML = '<div class="sv-empty">No entries yet.</div>';
                        return;
                    }
                    var html = '<div class="sv-table-container"><table><tr><th>Label</th><th>Values</th><th>Added by</th><th></th></tr>';
                    entries.forEach(function (e) {
                        var badge = e.added_by_type === 'admin'
                            ? ' <span class="sv-badge sv-badge-admin">staff</span>'
                            : ' <span class="sv-badge sv-badge-client">client</span>';
                        var adderName = esc(e.added_by_name || e.added_by_type);

                        html += '<tr data-id="' + e.id + '">' +
                            '<td style="font-weight:600;color:#334155;">' + esc(e.label) + '</td>' +
                            '<td class="sv-value-cell"><span class="sv-masked">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span> <button type="button" class="sv-link-btn sv-reveal">reveal</button></td>' +
                            '<td class="sv-meta">' + adderName + badge + '</td>' +
                            '<td><button type="button" class="sv-link-btn sv-delete" style="color:#ef4444;">remove</button></td>' +
                            '</tr>';
                    });
                    html += '</table></div>';
                    listEl.innerHTML = html;
                }
                function load() {
                    listEl.innerHTML = '<div class="sv-empty">Loading...</div>';
                    post('list').then(function (res) {
                        if (res.success) { render(res.entries); }
                        else { listEl.innerHTML = '<div class="sv-empty">' + esc(res.message || 'Failed to load.') + '</div>'; }
                    }).catch(function (err) {
                        listEl.innerHTML = '<div class="sv-empty">Connection error or session expired.</div>';
                    });
                }

                fab.addEventListener('click', function () { overlay.classList.add('sv-open'); load(); });
                overlay.querySelector('.sv-close').addEventListener('click', function () { overlay.classList.remove('sv-open'); });
                overlay.addEventListener('click', function (ev) { if (ev.target === overlay) { overlay.classList.remove('sv-open'); } });

                listEl.addEventListener('click', function (ev) {
                    var row = ev.target.closest('tr');
                    if (!row) { return; }
                    var id = row.getAttribute('data-id');
                    if (ev.target.classList.contains('sv-reveal')) {
                        post('reveal', { id: id }).then(function (res) {
                            if (res.success) {
                                row.querySelector('.sv-value-cell').innerHTML = '<span class="sv-value">' + esc(res.value) + '</span>';
                            } else {
                                alert(res.message || 'Failed to decrypt.');
                            }
                        }).catch(function (err) {
                            alert('Connection error or session expired.');
                        });
                    }
                    if (ev.target.classList.contains('sv-delete')) {
                        if (!confirm('Remove this entry permanently?')) { return; }
                        post('delete', { id: id }).then(function (res) {
                            if (res.success) { row.remove(); }
                            else { alert(res.message || 'Could not delete entry.'); }
                        }).catch(function (err) {
                            alert('Connection error or session expired.');
                        });
                    }
                });

                root.querySelector('.sv-add').addEventListener('click', function () {
                    var label = labelInput.value.trim();
                    var value = valueInput.value.trim();
                    if (!label || !value) { alert('Please fill in both the label and the value(s).'); return; }
                    post('add', { label: label, value: value }).then(function (res) {
                        if (res.success) { labelInput.value = ''; valueInput.value = ''; load(); }
                        else { alert(res.message || 'Could not add entry.'); }
                    }).catch(function (err) {
                        alert('Connection error or session expired.');
                    });
                });
            }

            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', init);
            } else {
                init();
            }
        })();
        </script>
        <?php
        return ob_get_clean();
    }
}
