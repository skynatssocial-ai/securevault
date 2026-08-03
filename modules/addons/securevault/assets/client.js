/**
 * SecureVault - client.js
 * Loaded via <script src="..."> tag injected by hooks.php.
 * Configuration variables are set on window.sv_config by the inline
 * <script> block output by Vault::renderClientWidgetLoader().
 */
(function () {
    'use strict';

    if (window.sv_client_widget_loaded) { return; }
    window.sv_client_widget_loaded = true;

    var cfg = window.sv_config || {};
    var ajaxUrl   = cfg.ajaxUrl   || '';
    var ticketId  = cfg.ticketId  || null;
    var isNew     = cfg.isNew     || false;
    var csrfToken = cfg.csrfToken || '';
    var STORAGE_KEY = 'securevault_pending_newticket';

    // ----------------------------------------------------------------
    // Utilities
    // ----------------------------------------------------------------

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
        d.innerText = (s == null) ? '' : String(s);
        return d.innerHTML;
    }

    function post(action, data) {
        data = data || {};
        data.action   = action;
        data.token    = csrfToken;
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

    // ----------------------------------------------------------------
    // Find the Ticket Information sidebar panel
    // ----------------------------------------------------------------

    function findTicketInfoPanel() {
        var panel = document.getElementById('Ticket_Information');
        if (!panel) { panel = document.querySelector('[id*="Ticket_Information"]'); }
        if (!panel) { panel = document.querySelector('[id*="TicketInformation"]'); }
        if (!panel) {
            var els = document.querySelectorAll('.panel, .card, .portlet');
            for (var i = 0; i < els.length; i++) {
                var t = els[i].innerText || '';
                if (t.indexOf('Ticket Information') !== -1 && t.indexOf('Department') !== -1) {
                    panel = els[i];
                    break;
                }
            }
        }
        return panel;
    }

    // ----------------------------------------------------------------
    // Build button
    // ----------------------------------------------------------------

    var fab = document.createElement('button');
    fab.type = 'button';

    var ticketInfoPanel = findTicketInfoPanel();

    if (ticketInfoPanel && ticketInfoPanel.parentNode) {
        fab.className = 'btn btn-primary btn-block sv-sidebar-btn';
        fab.innerText = 'Add Sensitive Data';
        if (ticketInfoPanel.nextSibling) {
            ticketInfoPanel.parentNode.insertBefore(fab, ticketInfoPanel.nextSibling);
        } else {
            ticketInfoPanel.parentNode.appendChild(fab);
        }
    } else {
        fab.className = 'sv-fab';
        fab.innerText = '\uD83D\uDD12 Add Sensitive Data';
        document.body.appendChild(fab);
    }

    // ----------------------------------------------------------------
    // Build modal overlay
    // ----------------------------------------------------------------

    var overlay = document.createElement('div');
    overlay.className = 'sv-overlay';

    var subText = isNew
        ? 'Anything added here will be attached to this ticket once you submit it, and permanently deleted when the ticket is closed.'
        : 'Everything here is permanently deleted the moment this ticket is closed.';

    overlay.innerHTML =
        '<div class="sv-modal">' +
            '<div class="sv-modal-header">' +
                '<h4>\uD83D\uDD12 Add Sensitive Data</h4>' +
                '<button type="button" class="sv-close">&times;</button>' +
            '</div>' +
            '<div class="sv-sub">' + subText + '</div>' +
            '<div class="sv-list"></div>' +
            '<div class="sv-form-group">' +
                '<input type="text" class="sv-label" placeholder="Label (e.g. cPanel login)">' +
                '<textarea class="sv-value" placeholder="Value(s) - e.g.&#10;Username: admin&#10;Password: ...&#10;URL: ..."></textarea>' +
            '</div>' +
            '<div class="sv-actions">' +
                '<button type="button" class="sv-btn sv-add sv-btn-primary">Add to vault</button>' +
            '</div>' +
        '</div>';
    document.body.appendChild(overlay);

    var listEl     = overlay.querySelector('.sv-list');
    var labelInput = overlay.querySelector('.sv-label');
    var valueInput = overlay.querySelector('.sv-value');

    // ----------------------------------------------------------------
    // Event wiring
    // ----------------------------------------------------------------

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

    // ----------------------------------------------------------------
    // Render helpers
    // ----------------------------------------------------------------

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
        }).catch(function () {
            listEl.innerHTML = '<div class="sv-empty">Connection error or session expired.</div>';
        });
    }

    function renderPending() { renderRows(pending, { pending: true }); }

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
            }).catch(function () { alert('Connection error or session expired.'); });
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
                }).catch(function () { alert('Connection error or session expired.'); });
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
            }).catch(function () { alert('Connection error or session expired.'); });
        }
    });

    // ----------------------------------------------------------------
    // New-ticket: attach pending entries to form on submit
    // ----------------------------------------------------------------

    if (isNew) {
        document.addEventListener('submit', function (ev) {
            var form = ev.target;
            if (!(form instanceof HTMLFormElement)) { return; }
            if (!form.querySelector('textarea[name="message"]')) { return; }
            var items = loadPending();
            if (!items.length) { return; }
            var hidden = document.createElement('input');
            hidden.type  = 'hidden';
            hidden.name  = 'securevault_pending';
            hidden.value = JSON.stringify(items);
            form.appendChild(hidden);
        }, true);
    }

}());
