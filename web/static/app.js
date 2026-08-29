(function () {
  'use strict';

  // i18n strings ship as a JSON data attribute (CSP forbids inline scripts)
  let I18N = {};
  let LANG = 'en';
  const i18nEl = document.getElementById('i18n-data');
  if (i18nEl) {
    try { I18N = JSON.parse(i18nEl.getAttribute('data-json')) || {}; } catch (e) { /* keep defaults */ }
    LANG = i18nEl.getAttribute('data-lang') || 'en';
  }
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

  // ---- disk usage bar ----------------------------------------------------------
  // Width is applied here rather than as an inline style attribute, which the
  // Content-Security-Policy (style-src 'self') deliberately forbids.
  document.querySelectorAll('.disk-fill[data-pct]').forEach((el) => {
    const pct = parseFloat(el.getAttribute('data-pct'));
    if (!isNaN(pct)) el.style.width = Math.max(0, Math.min(100, pct)) + '%';
  });

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

  // ---- keyed share links (decryption secret in the URL fragment) ---------------
  // The fragment never reaches the server in requests; move it into a
  // path-scoped cookie so the preview/download endpoints can unwrap the DEK.

  const dlRoot = document.getElementById('dl-root');
  if (dlRoot && dlRoot.getAttribute('data-keyed') === '1') {
    const fileId = dlRoot.getAttribute('data-file');
    const cookieName = dlRoot.getAttribute('data-cookie');
    const secret = (location.hash || '').replace(/^#/, '');
    if (/^[A-Za-z0-9_-]{40,50}$/.test(secret)) {
      let cookie = cookieName + '=' + secret + '; path=/files/' + fileId + '; max-age=21600; samesite=lax';
      if (location.protocol === 'https:') cookie += '; secure';
      document.cookie = cookie;
      document.querySelectorAll('[data-preview-src]').forEach((el) => {
        el.src = el.getAttribute('data-preview-src');
      });
    } else {
      const warn = document.getElementById('key-missing');
      if (warn) warn.hidden = false;
      const dlBtn = document.querySelector('.btn-download');
      if (dlBtn) dlBtn.classList.add('btn-disabled');
    }
  }

  // ---- end-to-end encrypted landing page ---------------------------------------
  // The ciphertext is fetched as-is and decrypted here; the plaintext never
  // exists outside this tab.

  const e2eRoot = document.getElementById('dl-root');
  if (e2eRoot && e2eRoot.getAttribute('data-e2e') === '1') {
    const E2E = window.KFS_E2E;
    const fileId = e2eRoot.getAttribute('data-file');
    const mode = e2eRoot.getAttribute('data-mode');
    const fileName = e2eRoot.getAttribute('data-name');
    const fileType = e2eRoot.getAttribute('data-type');
    const previewKind = e2eRoot.getAttribute('data-preview-kind');
    const errBox = document.getElementById('e2e-error');
    const keyMissing = document.getElementById('key-missing');
    const mainBox = document.getElementById('e2e-main');
    const dlBtn = document.getElementById('e2e-download');
    const progress = document.getElementById('e2e-progress');
    const statusEl = document.getElementById('e2e-status');
    const pctEl = document.getElementById('e2e-pct');
    const fillEl = document.getElementById('e2e-fill');

    let fileKey = null;
    let plainBlob = null;
    let inFlight = null;

    const fail = (msg) => {
      errBox.textContent = msg;
      errBox.hidden = false;
      progress.hidden = true;
    };
    const setProgress = (label, frac) => {
      progress.hidden = false;
      statusEl.textContent = label;
      const pct = Math.round(frac * 100);
      fillEl.style.width = pct + '%';
      pctEl.textContent = pct + '%';
    };

    // Fetch the ciphertext once and decrypt it; the result is reused by both
    // the preview and the download button so a share is counted once.
    async function getPlain() {
      if (plainBlob) return plainBlob;
      if (inFlight) return inFlight;
      inFlight = (async () => {
        const res = await fetch('/files/' + fileId + '/raw');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const total = Number(res.headers.get('Content-Length') || 0);
        const reader = res.body && res.body.getReader ? res.body.getReader() : null;
        let buf;
        if (reader) {
          const parts = [];
          let got = 0;
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            parts.push(value);
            got += value.length;
            if (total) setProgress(t('e2e_downloading'), got / total);
          }
          buf = await new Blob(parts).arrayBuffer();
        } else {
          buf = await res.arrayBuffer();
        }
        setProgress(t('e2e_decrypting'), 0);
        plainBlob = await E2E.decryptBuffer(buf, fileKey, fileType,
          (f) => setProgress(t('e2e_decrypting'), f));
        progress.hidden = true;
        return plainBlob;
      })();
      return inFlight;
    }

    async function renderPreview() {
      if (!previewKind) return;
      const box = document.getElementById('e2e-preview');
      let blob;
      try {
        blob = await getPlain();
      } catch (err) {
        fail(t('e2e_failed') + ' (' + err.message + ')');
        return;
      }
      box.classList.add('dl-preview-' + previewKind);
      if (previewKind === 'text') {
        const pre = document.createElement('pre');
        pre.className = 'e2e-text';
        pre.textContent = await blob.text();
        box.appendChild(pre);
      } else if (previewKind === 'pdf') {
        // Only frame a blob that really is a PDF: a lying content type must
        // not turn into an HTML document on a blob: origin.
        const head = new Uint8Array(await blob.slice(0, 5).arrayBuffer());
        if (String.fromCharCode.apply(null, head) !== '%PDF-') return;
        const frame = document.createElement('iframe');
        frame.src = URL.createObjectURL(blob);
        frame.title = fileName;
        box.appendChild(frame);
      } else {
        const el = document.createElement(
          previewKind === 'image' ? 'img' : previewKind === 'video' ? 'video' : 'audio');
        if (previewKind !== 'image') { el.controls = true; el.preload = 'metadata'; }
        el.src = URL.createObjectURL(blob);
        if (previewKind === 'image') el.alt = fileName;
        box.appendChild(el);
      }
      box.hidden = false;
    }

    async function startSession() {
      mainBox.hidden = false;
      await renderPreview();
    }

    dlBtn.addEventListener('click', async () => {
      if (!fileKey) return;
      dlBtn.disabled = true;
      try {
        const blob = await getPlain();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 30000);
      } catch (err) {
        fail(t('e2e_failed') + ' (' + err.message + ')');
      } finally {
        dlBtn.disabled = false;
      }
    });

    if (!E2E || !E2E.available) {
      fail(t('e2e_unsupported'));
      dlBtn.classList.add('btn-disabled');
    } else if (mode === 'url') {
      const secret = (location.hash || '').replace(/^#/, '');
      if (!/^[A-Za-z0-9_-]{43}$/.test(secret)) {
        keyMissing.hidden = false;
        dlBtn.classList.add('btn-disabled');
      } else {
        E2E.deriveUrlKey(E2E.b64uDecode(secret))
          .then((k) => { fileKey = k; return startSession(); })
          .catch(() => fail(t('e2e_failed')));
      }
    } else {
      const pwInput = document.getElementById('e2e-password');
      const unlockBtn = document.getElementById('e2e-unlock');
      const lockBox = document.getElementById('e2e-lock');
      const salt = E2E.b64uDecode(e2eRoot.getAttribute('data-salt') || '');
      const unlock = async () => {
        if (!pwInput.value) return;
        unlockBtn.disabled = true;
        errBox.hidden = true;
        try {
          setProgress(t('e2e_deriving'), 0.5);
          const { key, auth } = await E2E.derivePasswordKeys(pwInput.value, salt);
          const res = await fetch('/files/' + fileId, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'auth=' + encodeURIComponent(E2E.b64uEncode(auth)),
          });
          progress.hidden = true;
          if (res.status === 429) { fail(t('rate_limited')); return; }
          if (!res.ok) { fail(t('e2e_wrong_pw')); pwInput.value = ''; return; }
          fileKey = key;
          lockBox.hidden = true;
          await startSession();
        } catch (err) {
          fail(t('e2e_failed') + ' (' + err.message + ')');
        } finally {
          unlockBtn.disabled = false;
        }
      };
      unlockBtn.addEventListener('click', unlock);
      pwInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
    }
  }

  // ---- QR share modal ----------------------------------------------------------

  // QR codes are rendered entirely in the browser: for end-to-end links the
  // key lives in the fragment, which must never be sent to the server — not
  // even to draw a picture of it.
  function qrDataURL(text) {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    return qr.createDataURL(6, 4);
  }

  function showQR(shareUrl) {
    const overlay = document.createElement('div');
    overlay.className = 'qr-modal';
    const box = document.createElement('div');
    box.className = 'qr-box';
    const title = document.createElement('p');
    title.className = 'qr-title';
    title.textContent = t('qr_title');
    const img = document.createElement('img');
    img.src = qrDataURL(shareUrl);
    img.alt = 'QR';
    const urlP = document.createElement('p');
    urlP.className = 'qr-url';
    urlP.textContent = shareUrl;
    box.appendChild(title);
    box.appendChild(img);
    box.appendChild(urlP);
    overlay.appendChild(box);
    const close = () => overlay.remove();
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
    document.addEventListener('keydown', function esc(e) {
      if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esc); }
    });
    document.body.appendChild(overlay);
  }

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.btn-qr');
    if (!btn) return;
    e.preventDefault();
    showQR(new URL(btn.getAttribute('data-qr-url'), location.href).toString());
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

  // Browsers restore form state on reload/back-forward; always start clean.
  function resetOptions() {
    form.reset();
    if (expiresAtInput) expiresAtInput.value = '';
    if (expiresAtWrap) expiresAtWrap.hidden = true;
  }
  resetOptions();
  window.addEventListener('pageshow', (e) => {
    if (e.persisted) resetOptions();
  });

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

  async function uploadOne(file) {
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
    if (expiresSel && expiresSel.value === 'custom' && expiresAtInput && expiresAtInput.value) {
      // datetime-local is timezone-less; convert to UTC ISO for the server
      fd.append('expires_at', new Date(expiresAtInput.value).toISOString());
    } else if (expiresSel && expiresSel.value !== 'custom') {
      fd.append('expires_hours', expiresSel.value || '0');
    }
    if (maxDownloadsInput) fd.append('max_downloads', maxDownloadsInput.value || '0');

    // Encrypt in this tab before anything is sent. The password (when set) is
    // never transmitted: only a token derived from it on a separate KDF
    // branch, which cannot yield the file key.
    const E2E = window.KFS_E2E;
    const password = passwordInput ? passwordInput.value : '';
    let fragment = '';
    if (E2E && E2E.available) {
      try {
        let key;
        if (password) {
          const salt = E2E.randomBytes(E2E.SALT_LEN);
          status.textContent = t('e2e_deriving');
          const derived = await E2E.derivePasswordKeys(password, salt);
          key = derived.key;
          fd.append('auth_salt', E2E.b64uEncode(salt));
          fd.append('auth_verifier', E2E.b64uEncode(derived.auth));
        } else {
          const secret = E2E.randomBytes(E2E.KEY_LEN);
          fragment = '#' + E2E.b64uEncode(secret);
          key = await E2E.deriveUrlKey(secret);
        }
        const cipher = await E2E.encryptFile(file, key, (f) => {
          fill.style.width = Math.round(f * 100) + '%';
          status.textContent = t('e2e_encrypting');
        });
        fd.append('file', cipher, file.name);
        fd.append('e2e', '1');
        fd.append('plain_size', String(file.size));
        fd.append('content_type', file.type || 'application/octet-stream');
      } catch (err) {
        row.classList.add('queue-error');
        status.textContent = t('e2e_failed');
        return;
      }
    } else {
      // Fail closed. WebCrypto is missing precisely in insecure contexts
      // (plain HTTP), so falling back to a server-side upload would ship the
      // plaintext file and the password over the very connection that can't
      // be trusted — and would do it without telling anyone.
      row.classList.add('queue-error');
      status.textContent = t('e2e_unavailable');
      fill.style.width = '100%';
      toast(t('e2e_insecure'));
      return;
    }

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
        if (res && res.url) addLinkRow(row, res, fragment);
      } else if (xhr.status === 401) {
        row.classList.add('queue-error');
        status.textContent = t('login');
        setTimeout(() => (location.href = '/login?next=/'), 800);
      } else if (xhr.status === 413) {
        row.classList.add('queue-error');
        status.textContent = t('too_large');
      } else if (xhr.status === 507) {
        row.classList.add('queue-error');
        status.textContent = t('quota');
      } else if (xhr.status === 429) {
        row.classList.add('queue-error');
        status.textContent = t('rate_limited');
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

  function addLinkRow(row, res, fragment) {
    // For key-in-URL shares this is the only moment the complete link exists:
    // the fragment was generated in this tab and the server never sees it.
    const url = new URL(res.url + (fragment || ''), location.href).toString();
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
    btn.setAttribute('data-copy', url);
    btn.textContent = t('copy');

    const qrBtn = document.createElement('button');
    qrBtn.type = 'button';
    qrBtn.className = 'btn btn-ghost btn-sm btn-qr';
    qrBtn.setAttribute('data-qr-url', url);
    qrBtn.textContent = 'QR';

    wrap.appendChild(input);
    wrap.appendChild(btn);
    wrap.appendChild(qrBtn);
    if (res.hasPassword) {
      const chip = document.createElement('span');
      chip.className = 'chip chip-lock';
      chip.textContent = t('protected');
      row.querySelector('.queue-info').insertBefore(chip, row.querySelector('.queue-status'));
    }
    row.appendChild(wrap);
  }
})();
