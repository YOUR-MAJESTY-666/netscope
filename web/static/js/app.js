/**
 * NetScope v2 — Main application logic.
 *
 * Polls the Flask API every 1000ms, updates stat cards, charts,
 * connection strip, and manages the connection status badge.
 */
const POLL_INTERVAL = 1000;

let pollTimer;
let errorCount = 0;
let alertTotal = 0;

/**
 * Main polling function — fetches all API endpoints in parallel
 * and updates the dashboard UI.
 */
async function poll() {
  try {
    const [metricsRes, alertsRes, statusRes] = await Promise.all([
      fetch('/api/metrics'),
      fetch('/api/alerts?limit=50'),
      fetch('/api/status'),
    ]);

    if (!statusRes.ok) {
      setStatus('error');
      errorCount++;
      return;
    }

    const status  = await statusRes.json();

    if (status.running === false) {
      document.getElementById('control-panel-modal').classList.add('active');
      document.getElementById('btn-stop-capture').classList.add('hidden');
      setStatus('idle');
      return;
    } else {
      document.getElementById('control-panel-modal').classList.remove('active');
      document.getElementById('btn-stop-capture').classList.remove('hidden');
    }

    if (!metricsRes.ok || !alertsRes.ok) {
      setStatus('error');
      errorCount++;
      return;
    }

    const metrics = await metricsRes.json();
    const alerts  = await alertsRes.json();

    errorCount = 0;
    setStatus('ok');

    // Update stat cards
    setCard('val-rtt',    metrics.rtt_mean?.toFixed(1) ?? '—',   metrics.rtt_mean);
    setCard('val-jitter', metrics.jitter?.toFixed(1) ?? '—',     null);
    setCard('val-loss',   metrics.packet_loss_pct?.toFixed(1) ?? '—', null);
    setCard('val-p95',    metrics.p95?.toFixed(1) ?? '—',        metrics.p95);
    document.getElementById('val-pkts').textContent =
      formatNumber(metrics.total_packets ?? 0);

    // Update connection strip
    const target = status.target || '-';
    const port = status.port ? ':' + status.port : '';
    const proto = status.protocol ? status.protocol.toUpperCase() : '-';
    const label = status.label || '';
    document.getElementById('conn-target').textContent = `${target}${port}`;
    document.getElementById('conn-proto').textContent = proto;
    document.getElementById('conn-iface').textContent = status.interface || 'auto';

    // Alert count in connection strip
    alertTotal = alerts.length;
    const connAlerts = document.getElementById('conn-alerts');
    connAlerts.textContent = alertTotal;
    connAlerts.style.color = alertTotal > 0 ? 'var(--red)' : 'var(--green)';

    // Update session label in navbar
    const parts = [`${target}${port}`];
    if (proto && proto !== '-') parts.push(proto);
    if (label) parts.push(label);
    document.getElementById('session-label').textContent = parts.join(' - ');

    // Update uptime
    const up = Math.floor(status.uptime_seconds ?? 0);
    const h = Math.floor(up / 3600);
    const m = Math.floor((up % 3600) / 60);
    const s = up % 60;
    document.getElementById('uptime').textContent =
      `${pad(h)}:${pad(m)}:${pad(s)}`;

    // Footer session ID
    const footerSession = document.getElementById('footer-session');
    if (footerSession && status.session_id) {
      footerSession.textContent = status.session_id.substring(0, 8);
    }

    // RTT subtitle (min / max)
    const rttSubtitle = document.getElementById('rtt-subtitle');
    if (rttSubtitle && metrics.rtt_series && metrics.rtt_series.length > 0) {
      const rtts = metrics.rtt_series.map(p => p.rtt);
      const min = Math.min(...rtts).toFixed(1);
      const max = Math.max(...rtts).toFixed(1);
      rttSubtitle.textContent = `min ${min}ms / max ${max}ms`;
    }

    // Update charts
    Charts.updateRttLine(metrics.rtt_series ?? []);
    Charts.updateProtoPie(metrics.protocol_counts ?? {});
    Charts.updateTalkers(metrics.top_talkers ?? []);
    Charts.updateBandwidth(
      metrics.bps_in ?? 0,
      metrics.bps_out ?? 0,
      Date.now() / 1000,
    );
    Charts.updateRttHist(metrics.rtt_series ?? []);

    // Update alerts
    AlertsUI.render(alerts);

  } catch (err) {
    console.error('Poll error:', err);
    errorCount++;
    if (errorCount > 3) {
      setStatus('error');
    }
  }
}

/**
 * Update the status badge (LIVE / OFFLINE).
 */
function setStatus(state) {
  const badge = document.getElementById('status-badge');
  if (state === 'ok') {
    badge.textContent = '● LIVE';
    badge.className = 'badge badge-ok';
  } else if (state === 'idle') {
    badge.textContent = '● IDLE';
    badge.className = 'badge badge-error';
  } else {
    badge.textContent = '● OFFLINE';
    badge.className = 'badge badge-error';
  }
}

/**
 * Set a stat card value and optionally color it by RTT quality.
 */
function setCard(id, value, rtt) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = value;
  if (rtt !== null && rtt !== undefined) {
    if (rtt < 50) {
      el.style.color = 'var(--green)';
    } else if (rtt < 100) {
      el.style.color = 'var(--yellow)';
    } else {
      el.style.color = 'var(--red)';
    }
  }
}

/**
 * Clear all alerts via POST and update UI.
 */
async function clearAlerts() {
  try {
    await fetch('/api/clear_alerts', { method: 'POST' });
    AlertsUI.clear();
    alertTotal = 0;
    const connAlerts = document.getElementById('conn-alerts');
    if (connAlerts) {
      connAlerts.textContent = '0';
      connAlerts.style.color = 'var(--green)';
    }
  } catch (err) {
    console.error('Failed to clear alerts:', err);
  }
}

// Control Panel Logic

let presetsData = {};

async function loadPresets() {
  try {
    const res = await fetch('/api/presets');
    if (!res.ok) return;
    presetsData = await res.json();
    
    const sel = document.getElementById('sel-preset');
    for (const [key, p] of Object.entries(presetsData)) {
      const opt = document.createElement('option');
      opt.value = key;
      opt.textContent = p.name;
      sel.appendChild(opt);
    }
  } catch (err) {
    console.error('Failed to load presets', err);
  }
}

function toggleMode() {
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const fgTarget = document.getElementById('fg-target');
  const fgPreset = document.getElementById('fg-preset');
  
  if (mode === 'general') {
    fgTarget.style.display = 'none';
    fgPreset.style.display = 'none';
  } else {
    fgTarget.style.display = 'block';
    fgPreset.style.display = 'block';
  }
}

function applyPreset() {
  const key = document.getElementById('sel-preset').value;
  if (!key || !presetsData[key]) return;
  const p = presetsData[key];
  if (p.port) document.getElementById('inp-port').value = p.port;
  if (p.protocol) document.getElementById('sel-protocol').value = p.protocol;
}

async function startCapture() {
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const preset = document.getElementById('sel-preset').value;
  const target = document.getElementById('inp-target').value.trim();
  const port = document.getElementById('inp-port').value.trim();
  const protocol = document.getElementById('sel-protocol').value;
  const label = document.getElementById('inp-label').value.trim();

  const payload = { mode, preset, target, port, protocol, label };

  try {
    const res = await fetch('/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      poll(); // Immediate refresh
    }
  } catch (err) {
    console.error('Start failed', err);
  }
}

async function stopCapture() {
  try {
    await fetch('/api/stop', { method: 'POST' });
    poll(); // Immediate refresh to show modal
  } catch (err) {
    console.error('Stop failed', err);
  }
}

// Helpers

function pad(n) {
  return String(n).padStart(2, '0');
}

function formatNumber(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return String(n);
}

// Boot
document.addEventListener('DOMContentLoaded', () => {
  Charts.init();
  loadPresets();
  poll();
  pollTimer = setInterval(poll, POLL_INTERVAL);
});
