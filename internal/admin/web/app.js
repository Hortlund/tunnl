const csrf = document.querySelector('meta[name="csrf-token"]').content;
const $ = (selector) => document.querySelector(selector);
const tunnelRows = $('#tunnel-rows');
const tokenRows = $('#token-rows');
let toastTimer;
let savedDNSProvider = 'manual';
let savedDNSCredential = false;

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
  $('#metric-bytes').textContent = formatBytes(status.response_bytes);
  $('#metric-failed').textContent = formatNumber(status.failed_requests);
  $('#metric-uptime').textContent = formatUptime(status.uptime_seconds);
  $('#base-domain').textContent = `*.${status.base_domain}`;
  $('#last-refresh').textContent = 'just now';
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

Promise.all([loadStatus(), loadTokens(), loadDNS()]).catch((error) => showToast(error.message));
setInterval(() => loadStatus().catch(() => { $('#last-refresh').textContent = 'refresh failed'; }), 5000);
