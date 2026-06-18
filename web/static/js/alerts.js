/**
 * NetScope v2 - Alert table rendering.
 *
 * Manages the security alerts table in the dashboard.
 * Only appends new alerts (deduplicates by id) and caps at 100 rows.
 */
const AlertsUI = (() => {
  const tbody = document.getElementById('alerts-tbody');
  const badgeEl = document.getElementById('alert-badge');
  let knownIds = new Set();

  function render(alerts) {
    if (!alerts || alerts.length === 0) {
      if (knownIds.size === 0) {
        tbody.innerHTML =
          '<tr class="empty-row"><td colspan="5">No alerts - monitoring in progress</td></tr>';
      }
      updateBadge(0);
      return;
    }

    // Only append new alerts (by id)
    const newAlerts = alerts.filter(a => !knownIds.has(a.id));
    if (newAlerts.length === 0) {
      updateBadge(alerts.length);
      return;
    }

    // Remove empty placeholder row
    if (knownIds.size === 0) {
      tbody.innerHTML = '';
    }

    newAlerts.forEach(a => {
      knownIds.add(a.id);
      const tr = document.createElement('tr');
      tr.classList.add('alert-new');

      const time = new Date(a.timestamp * 1000).toLocaleTimeString();
      const sevClass = `severity-${a.severity.toLowerCase()}`;

      tr.innerHTML = `
        <td>${time}</td>
        <td><code>${escapeHtml(a.type)}</code></td>
        <td class="${sevClass}">${a.severity}</td>
        <td>${escapeHtml(a.description)}</td>
        <td><code>${escapeHtml(a.src_ip || '-')}</code></td>
      `;
      tbody.insertBefore(tr, tbody.firstChild);  // newest on top
    });

    // Keep max 100 rows in DOM
    while (tbody.rows.length > 100) {
      tbody.deleteRow(-1);
    }

    updateBadge(alerts.length);
  }

  function clear() {
    tbody.innerHTML =
      '<tr class="empty-row"><td colspan="5">No alerts - monitoring in progress</td></tr>';
    knownIds.clear();
    updateBadge(0);
  }

  function updateBadge(count) {
    if (count > 0) {
      badgeEl.textContent = count;
      badgeEl.classList.remove('hidden');
    } else {
      badgeEl.classList.add('hidden');
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  return { render, clear };
})();
