const csrf = document.querySelector('meta[name="csrf-token"]').content;
const $ = (selector) => document.querySelector(selector);
const tunnelRows = $('#tunnel-rows');
const tokenRows = $('#token-rows');
let toastTimer;
let savedDNSProvider = 'manual';
let savedDNSCredential = false;
const svgNS = 'http://www.w3.org/2000/svg';

async function api(path, options = {}) {
  const headers = { Accept: 'application/json', ...options.headers };
  if (options.body) headers['Content-Type'] = 'application/json';
  if (options.method && !['GET', 'HEAD'].includes(options.method)) headers['X-CSRF-Token'] = csrf;
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) { location.href = '/login'; throw new Error('Session expired'); }
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(body.error || response.statusText);
  }
  if (response.status === 204) return null;
  return response.json();
}

function cell(row, value, code = false) {
  const td = document.createElement('td');
  const node = code ? document.createElement('code') : document.createTextNode(value);
  if (code) { node.textContent = value; td.append(node); } else { td.append(node); }
  row.append(td);
  return td;
}

function formatNumber(value) { return new Intl.NumberFormat().format(value || 0); }
function formatBytes(value) {
  if (!value) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}
function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return days ? `${days}d ${hours}h` : hours ? `${hours}h ${minutes}m` : `${minutes}m`;
}
function formatTime(value, empty = 'Never') { return value ? new Date(value).toLocaleString() : empty; }
function formatRate(value, formatter = formatNumber) { return `${formatter(value || 0)}/s`; }
function formatDecimal(value, digits = 1) { return Number(value || 0).toFixed(digits); }
function formatRelativeDate(value) {
  if (!value) return 'Unavailable';
  const date = new Date(value);
  const days = Math.ceil((date.getTime() - Date.now()) / 86400000);
  const relative = days < 0 ? `${Math.abs(days)}d ago` : days === 0 ? 'today' : `in ${days}d`;
  return `${date.toLocaleDateString()} · ${relative}`;
}
function certificateStateLabel(state) {
  return ({ valid: 'Valid', renewal_due: 'Renewal due', renewing: 'Renewing', expired: 'Expired', revoked: 'Revoked', error: 'ACME error', unavailable: 'Unavailable' })[state] || state;
}
function showToast(message) {
  const toast = $('#toast'); toast.textContent = message; toast.classList.add('visible');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => toast.classList.remove('visible'), 2600);
}

async function loadStatus() {
  const status = await api('/api/v1/status');
  $('#server-version').textContent = status.version;
  $('#metric-active').textContent = formatNumber(status.active_tunnels);
  $('#metric-requests').textContent = formatNumber(status.total_requests);
  $('#metric-reservations').textContent = formatNumber(status.reservations);
  $('#metric-uptime').textContent = formatUptime(status.uptime_seconds);
  $('#base-domain').textContent = `*.${status.base_domain}`;
  $('#last-refresh').textContent = 'just now';
  const system = status.system || {};
  $('#resource-heap').textContent = formatBytes(system.heap_bytes);
  $('#resource-runtime').textContent = formatBytes(system.runtime_bytes);
  $('#resource-goroutines').textContent = formatNumber(system.goroutines);
  $('#resource-gc').textContent = formatNumber(system.gc_cycles);
  $('#resource-database').textContent = formatBytes(system.database_bytes);
  $('#resource-disk').textContent = system.disk_total_bytes ? `${formatBytes(system.disk_free_bytes)} / ${formatBytes(system.disk_total_bytes)}` : 'Unavailable';
  $('#resource-cpus').textContent = `${formatNumber(system.num_cpu)} logical`;
  $('#go-version').textContent = system.go_version || '';
  renderCertificate(status.certificate || {});
  tunnelRows.replaceChildren();
  for (const tunnel of status.tunnels || []) {
    const row = document.createElement('tr');
    cell(row, `${tunnel.domain}.${status.base_domain}`);
    cell(row, tunnel.remote, true);
    cell(row, formatTime(tunnel.connected_at));
    tunnelRows.append(row);
  }
  $('#tunnels-empty').hidden = Boolean(status.tunnels?.length);
}

function renderCertificate(certificate) {
  const badge = $('#certificate-badge');
  badge.textContent = certificateStateLabel(certificate.state || 'unavailable');
  badge.dataset.state = certificate.state || 'unavailable';
  const needsAttention = ['error', 'expired', 'revoked', 'unavailable'].includes(certificate.state);
  $('#server-health').dataset.state = needsAttention ? 'warning' : 'healthy';
  $('#health-label').textContent = needsAttention ? 'Needs attention' : 'Operational';
  $('#certificate-name').textContent = certificate.names?.join(', ') || 'No certificate loaded';
  $('#certificate-issuer').textContent = certificate.issuer || certificate.provider || 'Self-signed';
  $('#certificate-mode').textContent = `${certificate.mode || 'unavailable'}${certificate.staging ? ' · staging' : ''}`;
  $('#certificate-expires').textContent = formatRelativeDate(certificate.not_after);
  $('#certificate-renewal').textContent = formatRelativeDate(certificate.renewal_window_start);
  $('#certificate-event').textContent = certificate.last_event ? `${certificate.last_event.replaceAll('_', ' ')} · ${formatTime(certificate.last_event_at)}` : 'No ACME event recorded';
  $('#certificate-serial').textContent = certificate.serial || '—';
  const error = $('#certificate-error');
  error.textContent = certificate.last_error || '';
  error.hidden = !certificate.last_error;
}

function svgElement(name, attributes = {}) {
  const element = document.createElementNS(svgNS, name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

function renderChart(id, samples, series, formatter, minimumMax = 0) {
  const chart = $(`#${id}`);
  const plot = chart.querySelector('.chart-plot');
  plot.replaceChildren();
  if (!samples.length) {
    const empty = document.createElement('p'); empty.className = 'chart-empty'; empty.textContent = 'Waiting for telemetry'; plot.append(empty); return;
  }
  const width = 620; const height = 176; const top = 8; const bottom = 24; const graphHeight = height - top - bottom;
  const values = samples.flatMap((sample) => series.map((item) => Number(sample[item.key] || 0)));
  const max = Math.max(minimumMax, ...values, 0.0001) * 1.08;
  const svg = svgElement('svg', { viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': `${id.replaceAll('-', ' ')} time series` });
  for (let index = 0; index < 4; index += 1) {
    const y = top + graphHeight * index / 3;
    svg.append(svgElement('line', { x1: 0, y1: y, x2: width, y2: y, class: 'chart-gridline' }));
  }
  for (const item of series) {
    const points = samples.map((sample, index) => {
      const x = samples.length === 1 ? width : index / (samples.length - 1) * width;
      const y = top + graphHeight - Number(sample[item.key] || 0) / max * graphHeight;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    svg.append(svgElement('polyline', { points, class: `chart-line ${item.className}` }));
  }
  const start = new Date(samples[0].timestamp);
  const end = new Date(samples[samples.length - 1].timestamp);
  const startLabel = svgElement('text', { x: 0, y: height - 4, class: 'chart-axis' }); startLabel.textContent = start.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); svg.append(startLabel);
  const endLabel = svgElement('text', { x: width, y: height - 4, class: 'chart-axis', 'text-anchor': 'end' }); endLabel.textContent = end.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); svg.append(endLabel);
  const cursor = svgElement('line', { y1: top, y2: top + graphHeight, class: 'chart-cursor' }); cursor.hidden = true; svg.append(cursor);
  const tooltip = document.createElement('div'); tooltip.className = 'chart-tooltip'; tooltip.hidden = true; plot.append(svg, tooltip);
  svg.addEventListener('pointermove', (event) => {
    const bounds = svg.getBoundingClientRect();
    const ratio = Math.max(0, Math.min(1, (event.clientX - bounds.left) / bounds.width));
    const index = Math.round(ratio * (samples.length - 1)); const sample = samples[index]; const x = index / Math.max(1, samples.length - 1) * width;
    cursor.setAttribute('x1', x); cursor.setAttribute('x2', x); cursor.hidden = false;
    tooltip.innerHTML = `<time>${new Date(sample.timestamp).toLocaleTimeString()}</time>${series.map((item) => `<span><i class="legend ${item.className}"></i>${item.label}: ${formatter(Number(sample[item.key] || 0))}</span>`).join('')}`;
    tooltip.hidden = false;
  });
  svg.addEventListener('pointerleave', () => { cursor.hidden = true; tooltip.hidden = true; });
}

async function loadMetrics() {
  const metrics = await api('/api/v1/metrics');
  const samples = metrics.samples || [];
  const latest = samples.at(-1) || {};
  $('#sample-count').textContent = samples.length ? `${samples.length} samples · ${metrics.sample_interval_seconds}s interval` : 'Collecting samples';
  $('#metric-request-rate').textContent = formatRate(latest.requests_per_second, (value) => formatDecimal(value, 1));
  const errorPercent = latest.requests_per_second ? latest.failures_per_second / latest.requests_per_second * 100 : 0;
  $('#metric-error-rate').textContent = `${formatDecimal(errorPercent, 1)}%`;
  $('#metric-byte-rate').textContent = formatRate(latest.bytes_per_second, formatBytes);
  $('#requests-chart-value').textContent = formatRate(latest.requests_per_second, (value) => formatDecimal(value, 1));
  $('#bandwidth-chart-value').textContent = formatRate(latest.bytes_per_second, formatBytes);
  $('#tunnel-chart-value').textContent = formatNumber(latest.active_tunnels);
  $('#cpu-chart-value').textContent = `${formatDecimal(latest.cpu_percent, 1)}%`;
  renderChart('requests-chart', samples, [{ key: 'requests_per_second', className: 'request', label: 'Requests/s' }, { key: 'failures_per_second', className: 'failure', label: 'Failures/s' }], (value) => `${formatDecimal(value, 2)}/s`);
  renderChart('bandwidth-chart', samples, [{ key: 'bytes_per_second', className: 'bandwidth', label: 'Response' }], (value) => `${formatBytes(value)}/s`);
  renderChart('tunnel-chart', samples, [{ key: 'active_tunnels', className: 'tunnel', label: 'Tunnels' }], (value) => formatNumber(value), 1);
  renderChart('cpu-chart', samples, [{ key: 'cpu_percent', className: 'cpu', label: 'CPU' }], (value) => `${formatDecimal(value, 1)}%`, 10);
}

async function loadTokens() {
  const tokens = await api('/api/v1/tokens');
  tokenRows.replaceChildren();
  for (const token of tokens || []) {
    const row = document.createElement('tr');
    cell(row, token.label);
    cell(row, `${token.prefix}…`, true);
    cell(row, formatTime(token.created_at));
    cell(row, formatTime(token.last_used_at));
    const action = cell(row, '');
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'revoke'; button.textContent = 'Revoke';
    button.addEventListener('click', async () => {
      if (!confirm(`Revoke “${token.label}” and disconnect its tunnels?`)) return;
      button.disabled = true;
      try { await api(`/api/v1/tokens/${encodeURIComponent(token.id)}`, { method: 'DELETE' }); await Promise.all([loadTokens(), loadStatus()]); showToast('Token revoked'); }
      catch (error) { showToast(error.message); button.disabled = false; }
    });
    action.append(button); tokenRows.append(row);
  }
  $('#tokens-empty').hidden = Boolean(tokens?.length);
}

async function loadDNS() {
  const config = await api('/api/v1/dns');
  savedDNSProvider = config.provider;
  savedDNSCredential = config.credential_available;
  $('#dns-provider').value = config.provider;
  $('#dns-zone').value = config.zone || '';
  $('#dns-target').value = config.target || '';
  $('#dns-credential').textContent = config.provider === 'cloudflare' ? (config.credential_available ? 'API token available' : 'API token missing') : 'No API credential needed';
  $('#dns-reconcile').disabled = config.provider !== 'cloudflare';
}

$('#token-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button'); button.disabled = true;
  try {
    const created = await api('/api/v1/tokens', { method: 'POST', body: JSON.stringify({ label: $('#token-label').value }) });
    $('#created-secret').textContent = created.secret; $('#token-label').value = ''; $('#secret-dialog').showModal(); await loadTokens();
  } catch (error) { showToast(error.message); }
  finally { button.disabled = false; }
});

$('#copy-secret').addEventListener('click', async () => {
  await navigator.clipboard.writeText($('#created-secret').textContent); showToast('Copied to clipboard');
});

$('#dns-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]'); button.disabled = true;
  try {
    await api('/api/v1/dns', { method: 'PUT', body: JSON.stringify({ provider: $('#dns-provider').value, zone: $('#dns-zone').value, target: $('#dns-target').value }) });
    await loadDNS(); showToast('DNS settings saved');
  } catch (error) { showToast(error.message); }
  finally { button.disabled = false; }
});

$('#dns-reconcile').addEventListener('click', async (event) => {
  event.currentTarget.disabled = true;
  try { const result = await api('/api/v1/dns/reconcile', { method: 'POST', body: '{}' }); showToast(result.message); }
  catch (error) { showToast(error.message); }
  finally { await loadDNS(); }
});

$('#dns-provider').addEventListener('change', () => {
  const provider = $('#dns-provider').value;
  const savedCloudflare = provider === 'cloudflare' && savedDNSProvider === 'cloudflare';
  $('#dns-reconcile').disabled = !savedCloudflare;
  $('#dns-credential').textContent = provider === 'cloudflare' ? (savedCloudflare ? (savedDNSCredential ? 'API token available' : 'API token missing') : 'Save before reconciling') : 'No API credential needed';
});
$('#logout').addEventListener('click', async () => { await api('/logout', { method: 'POST', body: '{}' }); location.href = '/login'; });

async function refreshLive() {
  try { await Promise.all([loadStatus(), loadMetrics()]); }
  catch (error) {
    $('#last-refresh').textContent = 'refresh failed';
    $('#server-health').dataset.state = 'warning';
    $('#health-label').textContent = 'Admin API unavailable';
    throw error;
  }
}

Promise.all([refreshLive(), loadTokens(), loadDNS()]).catch((error) => showToast(error.message));
setInterval(() => refreshLive().catch(() => {}), 5000);
