// Diagnostic: runs immediately, writes to visible DOM elements
(function() {
  var d = document.getElementById('diag');
  if (!d) return;
  d.style.display = 'block';
  var t = window.__TAURI__;
  var keys = t ? Object.keys(t).join(',') : 'MISSING';
  d.textContent = 'JS✓ __TAURI__=' + (t ? 'ok' : 'MISSING') + ' keys=[' + keys + ']';
  var sub = document.getElementById('systemStateText');
  if (sub) sub.textContent = t ? 'JS+Tauri OK' : 'Tauri MISSING';
})();

window.onerror = function(msg, _src, line) {
  var d = document.getElementById('diag');
  if (d) { d.style.display='block'; d.style.color='#FF453A'; d.textContent = 'ERR L'+line+': '+msg; }
};

function el(id) { return document.getElementById(id); }

function showError(msg) {
  var bar = el('error-bar');
  bar.style.cssText = 'display:block;background:#FF453A;color:#fff;font-size:11px;padding:4px 10px;';
  bar.textContent = msg;
  setTimeout(function() { bar.style.display='none'; }, 7000);
}

async function ipc(req) {
  try {
    var t = window.__TAURI__;
    if (!t) { showError('__TAURI__ not found'); return null; }
    var fn = t.invoke || (t.tauri && t.tauri.invoke);
    if (!fn) { showError('invoke not found. Keys:' + Object.keys(t).join(',')); return null; }
    return await fn('send_ipc_command', { req: req });
  } catch(e) {
    showError('IPC error: ' + e);
    return null;
  }
}

var loggedIn = false;
var networkOpen = false;
var connOpen = false;
var pollTimer = null;

function setLoggedIn(email, imageUrl) {
  loggedIn = true;
  el('userName').textContent = email || 'User Profile';
  el('userSub').textContent = 'Connected';
  el('accountChevron').style.display = 'inline';
  el('avatarBox').innerHTML = imageUrl
    ? '<img src="'+imageUrl+'" alt="">'
    : '<span>'+(email||'U')[0].toUpperCase()+'</span>';
  el('mainToggle').checked = true;
  el('mainToggle').disabled = false;
  el('systemStateText').textContent = 'Connected';
  el('connectedSection').style.display = 'block';
  el('diag').style.display = 'none';
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

function setLoggedOut() {
  loggedIn = false;
  el('userName').textContent = 'Not logged in';
  el('userSub').textContent = 'Click to sign in';
  el('avatarBox').innerHTML = '<span>?</span>';
  el('accountChevron').style.display = 'none';
  el('mainToggle').checked = false;
  el('mainToggle').disabled = true;
  el('systemStateText').textContent = 'Disconnected';
  el('connectedSection').style.display = 'none';
}

async function updateStatus() {
  var resp = await ipc('GetStatus');
  if (!resp || !resp.Status) return;
  var s = resp.Status;
  if (s.is_active) setLoggedIn(s.email, s.image_url);
  else if (!loggedIn) el('systemStateText').textContent = 'Disconnected';
}

el('btnAccount').addEventListener('mousedown', async function() {
  if (loggedIn) { el('account-modal').style.display = 'block'; return; }
  el('userSub').textContent = 'Opening browser…';
  var resp = await ipc('StartOAuthFlow');
  if (!resp || resp.Error) { showError(resp ? resp.Error : 'failed'); return; }
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(updateStatus, 2000);
});

el('modalDashboard').addEventListener('mousedown', function() {
  try { window.__TAURI__.shell.open('https://www.bluehashsecurity.com/dashboard/devices'); }
  catch(e) { showError(''+e); }
  el('account-modal').style.display = 'none';
});

el('modalLogout').addEventListener('mousedown', function() {
  el('account-modal').style.display = 'none';
  setLoggedOut();
});

document.addEventListener('mousedown', function(e) {
  var modal = el('account-modal');
  if (modal.style.display === 'block') {
    if (!el('account-modal-box').contains(e.target) && !el('btnAccount').contains(e.target)) {
      modal.style.display = 'none';
    }
  }
});

el('btnNetwork').addEventListener('mousedown', async function() {
  networkOpen = !networkOpen;
  var panel = el('networkList');
  if (networkOpen) {
    panel.innerHTML = '<div class="list-item">Loading…</div>';
    panel.classList.add('open');
    var resp = await ipc('GetNetworkDevices');
    if (resp && resp.NetworkDevices) {
      panel.innerHTML = resp.NetworkDevices.length
        ? resp.NetworkDevices.map(function(d){return '<div class="list-item">'+d+'</div>';}).join('')
        : '<div class="list-item">No devices</div>';
    }
  } else { panel.classList.remove('open'); }
});

el('btnConnections').addEventListener('mousedown', async function() {
  connOpen = !connOpen;
  var panel = el('connList');
  if (connOpen) {
    panel.innerHTML = '<div class="list-item">Loading…</div>';
    panel.classList.add('open');
    var resp = await ipc('GetConnections');
    if (resp && resp.Connections) {
      panel.innerHTML = resp.Connections.length
        ? resp.Connections.map(function(c){return '<div class="list-item">'+c+'</div>';}).join('')
        : '<div class="list-item">No connections</div>';
    }
  } else { panel.classList.remove('open'); }
});

el('btnSync').addEventListener('mousedown', async function() {
  var resp = await ipc('SyncKeys');
  if (!resp || resp.Error) { showError(resp ? resp.Error : 'Sync failed'); return; }
  el('diag').style.cssText = 'display:block;color:#30D158;font-size:10px;padding:3px 10px;background:#111;';
  el('diag').textContent = 'Keys synced ✓';
  setTimeout(function(){ el('diag').style.display='none'; }, 3000);
});

el('btnQuit').addEventListener('mousedown', async function() {
  await ipc('RotatePnk');
  try { window.__TAURI__.process.exit(0); } catch(e) { window.close(); }
});

setInterval(updateStatus, 5000);
updateStatus();
