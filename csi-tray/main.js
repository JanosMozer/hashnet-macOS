    window.onerror = function(msg, url, line, col, error) {
      document.getElementById('systemStateText').textContent = 'Err: ' + msg;
      document.getElementById('systemStateText').style.color = 'var(--red)';
    };
    window.onunhandledrejection = function(event) {
      document.getElementById('systemStateText').textContent = 'Rej: ' + event.reason;
      document.getElementById('systemStateText').style.color = 'var(--red)';
    };

    function log(msg) {
      const a = document.getElementById('logArea');
      if(a) {
        a.value += msg + '\n';
        a.scrollTop = a.scrollHeight;
      }
    }

    const t = window.__TAURI__;
    log('__TAURI__ keys: ' + (t ? Object.keys(t).join(',') : 'null'));
    const invoke = (t && (t.invoke || t.tauri?.invoke)) || null;
    log('invoke available: ' + !!invoke);

    if (!invoke) {
      document.getElementById('systemStateText').textContent = 'Tauri API Missing';
      document.getElementById('systemStateText').style.color = 'var(--red)';
    }

    function showError(msg) {
      log('ERR: ' + msg);
      const bar = document.getElementById('error-bar');
      if (!bar) return;
      bar.textContent = msg;
      bar.style.display = 'block';
      setTimeout(() => { bar.style.display = 'none'; }, 6000);
    }

    async function ipc(req) {
      log('ipc() req: ' + JSON.stringify(req));
      if (!invoke) return;
      try {
        const r = await invoke('send_ipc_command', { req });
        log('ipc() res: ' + JSON.stringify(r));
        return r;
      } catch (e) {
        showError(String(e));
        throw e;
      }
    }

    document.getElementById('btnTest').addEventListener('click', () => {
      log('Test button clicked');
      ipc('GetStatus').then(r => log('Test res: ' + JSON.stringify(r))).catch(e => log('Test err: ' + e));
    });

    ipc('GetStatus').then(res => {
      document.getElementById('systemStateText').textContent = 'Ping Success';
    }).catch(e => {
      document.getElementById('systemStateText').textContent = 'Ping Fail: ' + e;
    });

    let loggedInUser = null;
    let networkOpen = false;
    let connOpen = false;

    document.getElementById('btnAccount').addEventListener('click', async () => {
      if (loggedInUser) return;
      const mockId = crypto.randomUUID();
      try {
        const resp = await ipc({ Login: { user_id: mockId } });
        if (resp && resp.Error) { showError('Login: ' + resp.Error); return; }
        loggedInUser = mockId;
        document.getElementById('userName').textContent = 'mozer';
        document.getElementById('userSub').textContent = mockId.slice(0, 18) + '…';
        document.getElementById('avatarFallback').textContent = 'M';
        await updateStatus();
      } catch (_) {}
    });

    document.getElementById('btnNetwork').addEventListener('click', async () => {
      if (!loggedInUser) { showError('Login first'); return; }
      networkOpen = !networkOpen;
      const panel = document.getElementById('networkList');
      if (networkOpen) {
        panel.innerHTML = '<div class="list-empty">Loading…</div>';
        panel.classList.add('open');
        try {
          const resp = await ipc('GetNetworkDevices');
          if (resp?.NetworkDevices) {
            const devs = resp.NetworkDevices;
            document.getElementById('networkCount').textContent = devs.length;
            panel.innerHTML = devs.length
              ? devs.map(d => `<div class="list-item">${d.slice(0,28)}…</div>`).join('')
              : '<div class="list-empty">No devices</div>';
          } else {
            panel.innerHTML = `<div class="list-empty">${resp?.Error ?? 'Error'}</div>`;
          }
        } catch (_) { panel.innerHTML = '<div class="list-empty">Error</div>'; }
      } else {
        panel.classList.remove('open');
      }
    });

    document.getElementById('btnConnections').addEventListener('click', async () => {
      if (!loggedInUser) { showError('Login first'); return; }
      connOpen = !connOpen;
      const panel = document.getElementById('connList');
      if (connOpen) {
        panel.innerHTML = '<div class="list-empty">Loading…</div>';
        panel.classList.add('open');
        try {
          const resp = await ipc('GetConnections');
          if (resp?.Connections) {
            const cs = resp.Connections;
            document.getElementById('connCount').textContent = cs.length;
            panel.innerHTML = cs.length
              ? cs.map(c => `<div class="list-item">${c}</div>`).join('')
              : '<div class="list-empty">No accepted connections</div>';
          } else {
            panel.innerHTML = `<div class="list-empty">${resp?.Error ?? 'Error'}</div>`;
          }
        } catch (_) { panel.innerHTML = '<div class="list-empty">Error</div>'; }
      } else {
        panel.classList.remove('open');
      }
    });

    document.getElementById('btnSync').addEventListener('click', async () => {
      try {
        const resp = await ipc('SyncKeys');
        if (resp?.Error) showError('Sync: ' + resp.Error);
        else showError('Keys synced ');
        document.getElementById('error-bar').style.background = resp?.Error ? 'var(--red)' : 'var(--green)';
      } catch (_) {}
    });

    document.getElementById('btnQuit').addEventListener('click', async () => {
      await ipc('RotatePnk').catch(() => {});
      window.__TAURI__?.process?.exit(0) ?? window.close();
    });

    async function updateStatus() {
      try {
        const resp = await ipc('GetStatus');
        const s = resp?.Status;
        if (!s) return;

        const { hostname, is_active, state } = s;
        const dot = `<span class="status-dot" style="background:${is_active ? 'var(--green)' : 'var(--red)'}"></span>`;
        const label = is_active ? 'Active' : 'Disabled';
        document.getElementById('deviceStatus').innerHTML =
          `<strong>${hostname}</strong> — ${dot}${label}`;

        document.getElementById('systemStateText').textContent =
          state.includes('Ready') ? 'Connected' : 'Disconnected';

        document.getElementById('decryptionToggle').checked =
          !state.includes('Waiting');
      } catch (e) {
        document.getElementById('deviceStatus').innerHTML =
          `<span style="color:var(--red)">Daemon offline</span>`;
        document.getElementById('systemStateText').textContent = 'Offline';
      }
    }

    setInterval(updateStatus, 5000);
    updateStatus();
