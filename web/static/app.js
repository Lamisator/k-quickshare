(function () {
  'use strict';

  const I18N = window.I18N || {};
  const LANG = window.LANG || 'en';
  const t = (key, arg) => {
    let s = I18N[key] || key;
    if (arg !== undefined) s = s.replace('%s', arg);
    return s;
  };

  // human-readable transfer rate, localized decimal (e.g. "3.2 MB/s" / "3,2 MB/s")
  const rateFmt = new Intl.NumberFormat(LANG === 'de' ? 'de-DE' : 'en-GB', {
    maximumFractionDigits: 1,
  });
  function fmtRate(bytesPerSec) {
    const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
    let v = bytesPerSec;
    let i = 0;
    while (v >= 1000 && i < units.length - 1) {
      v /= 1000;
      i++;
    }
    return rateFmt.format(v) + ' ' + units[i];
  }

  // ---- toast ---------------------------------------------------------------

  let toastEl;
  function toast(msg) {
    if (!toastEl) {
      toastEl = document.createElement('div');
      toastEl.className = 'toast';
      document.body.appendChild(toastEl);
    }
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => toastEl.classList.remove('show'), 1800);
  }

  // ---- mobile sidebar toggle -------------------------------------------------

  const sidebarToggle = document.getElementById('sidebar-toggle');
  if (sidebarToggle) {
    sidebarToggle.addEventListener('click', () => {
      sidebarToggle.closest('.sidebar').classList.toggle('open');
    });
  }

  // ---- localized timestamps --------------------------------------------------

  document.querySelectorAll('time[data-ts]').forEach((el) => {
    const d = new Date(el.getAttribute('data-ts'));
    if (isNaN(d)) return;
    el.textContent = d.toLocaleString(LANG === 'de' ? 'de-DE' : 'en-GB', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
    el.title = d.toLocaleString();
  });

  // ---- copy-link buttons (works for dynamically added ones too) --------------

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.btn-copy');
    if (!btn) return;
    e.preventDefault();
    const url = new URL(btn.getAttribute('data-copy'), location.href).toString();
    try {
      await navigator.clipboard.writeText(url);
      btn.classList.add('copied');
      toast(t('toast_copied'));
      setTimeout(() => btn.classList.remove('copied'), 1400);
    } catch (err) {
      toast(t('toast_copyerr'));
    }
  });

  // ---- localized delete confirmations -----------------------------------------

  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (e) => {
      if (!confirm(form.getAttribute('data-confirm'))) e.preventDefault();
    });
  });

  // ---- history page: live search ----------------------------------------------

  const search = document.getElementById('file-search');
  const fileList = document.getElementById('file-list');
  if (search && fileList) {
    const noResults = document.getElementById('no-results');
    search.addEventListener('input', () => {
      const q = search.value.trim().toLowerCase();
      let visible = 0;
      fileList.querySelectorAll('.file-item').forEach((li) => {
        const hit = !q || (li.getAttribute('data-search') || '').toLowerCase().includes(q);
        li.hidden = !hit;
        if (hit) visible++;
      });
      if (noResults) noResults.hidden = visible > 0;
    });
  }

  // ---- upload page --------------------------------------------------------------

  const form = document.getElementById('upload-form');
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const queue = document.getElementById('queue');
  if (!form || !dropzone || !fileInput || !queue) return;

  const sessionSection = document.getElementById('session-uploads');
  const expiresSel = document.getElementById('opt-expires');
  const expiresAtWrap = document.getElementById('opt-expires-at-wrap');
  const expiresAtInput = document.getElementById('opt-expires-at');
  const passwordInput = document.getElementById('opt-password');
  const maxDownloadsInput = document.getElementById('opt-max');

  form.addEventListener('submit', (e) => e.preventDefault());

  // custom expiry date picker
  if (expiresSel && expiresAtWrap && expiresAtInput) {
    expiresSel.addEventListener('change', () => {
      const custom = expiresSel.value === 'custom';
      expiresAtWrap.hidden = !custom;
      if (custom && !expiresAtInput.value) {
        // default to one week from now, minute precision, local time
        const d = new Date(Date.now() + 7 * 24 * 3600 * 1000);
        d.setSeconds(0, 0);
        const pad = (n) => String(n).padStart(2, '0');
        expiresAtInput.value =
          d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
          'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
        expiresAtInput.min = new Date(Date.now() + 5 * 60 * 1000).toISOString().slice(0, 16);
      }
      if (custom) expiresAtInput.focus();
    });
  }

  ['dragenter', 'dragover'].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.add('dropzone-hover');
    })
  );
  ['dragleave', 'drop'].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.remove('dropzone-hover');
    })
  );
  dropzone.addEventListener('drop', (e) => {
    if (e.dataTransfer && e.dataTransfer.files) handleFiles(e.dataTransfer.files);
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files) handleFiles(e.target.files);
    fileInput.value = '';
  });

  function handleFiles(files) {
    if (!files || files.length === 0) return;
    if (sessionSection) sessionSection.hidden = false;
    for (const file of files) uploadOne(file);
  }

  function uploadOne(file) {
    const row = document.createElement('div');
    row.className = 'queue-item';
    row.innerHTML = `
      <div class="queue-info">
        <span class="queue-name"></span>
        <span class="queue-status">0%</span>
      </div>
      <div class="queue-bar"><div class="queue-fill"></div></div>
    `;
    row.querySelector('.queue-name').textContent = file.name;
    queue.prepend(row);

    const fill = row.querySelector('.queue-fill');
    const status = row.querySelector('.queue-status');

    const fd = new FormData();
    fd.append('file', file);
    if (expiresSel && expiresSel.value === 'custom' && expiresAtInput && expiresAtInput.value) {
      // datetime-local is timezone-less; convert to UTC ISO for the server
      fd.append('expires_at', new Date(expiresAtInput.value).toISOString());
    } else if (expiresSel && expiresSel.value !== 'custom') {
      fd.append('expires_hours', expiresSel.value || '0');
    }
    if (passwordInput) fd.append('password', passwordInput.value || '');
    if (maxDownloadsInput) fd.append('max_downloads', maxDownloadsInput.value || '0');

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/upload');
    xhr.setRequestHeader('Accept', 'application/json');
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

    let lastTime = performance.now();
    let lastLoaded = 0;
    let emaRate = 0; // exponential moving average, bytes/sec

    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      const now = performance.now();
      const dt = (now - lastTime) / 1000;
      if (dt > 0.15) {
        const inst = (e.loaded - lastLoaded) / dt;
        emaRate = emaRate ? emaRate * 0.7 + inst * 0.3 : inst;
        lastTime = now;
        lastLoaded = e.loaded;
      }
      const pct = (e.loaded / e.total) * 100;
      fill.style.width = pct + '%';
      status.textContent =
        Math.min(99, Math.round(pct)) + '%' + (emaRate > 0 ? ' · ' + fmtRate(emaRate) : '');
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 400) {
        fill.style.width = '100%';
        row.classList.add('queue-done');
        status.textContent = t('done');
        let res = null;
        try { res = JSON.parse(xhr.responseText); } catch (e) { /* ignore */ }
        if (res && res.url) addLinkRow(row, res);
      } else if (xhr.status === 401) {
        row.classList.add('queue-error');
        status.textContent = t('login');
        setTimeout(() => (location.href = '/login?next=/'), 800);
      } else if (xhr.status === 413) {
        row.classList.add('queue-error');
        status.textContent = t('too_large');
      } else {
        row.classList.add('queue-error');
        status.textContent = t('failed');
      }
    };
    xhr.onerror = () => {
      row.classList.add('queue-error');
      status.textContent = t('network');
    };
    xhr.send(fd);
  }

  function addLinkRow(row, res) {
    const url = new URL(res.url, location.href).toString();
    const wrap = document.createElement('div');
    wrap.className = 'queue-link';

    const input = document.createElement('input');
    input.type = 'text';
    input.readOnly = true;
    input.value = url;
    input.addEventListener('focus', () => input.select());

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-ghost btn-sm btn-copy';
    btn.setAttribute('data-copy', res.url);
    btn.textContent = t('copy');

    wrap.appendChild(input);
    wrap.appendChild(btn);
    if (res.hasPassword) {
      const chip = document.createElement('span');
      chip.className = 'chip chip-lock';
      chip.textContent = t('protected');
      row.querySelector('.queue-info').insertBefore(chip, row.querySelector('.queue-status'));
    }
    row.appendChild(wrap);
  }
})();
