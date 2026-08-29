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
  // %d and %s are interchangeable here: the same catalogue feeds Go's Sprintf
  // (which needs %d for counts) and this one-argument substitution.
  const t = (key, arg) => {
    let s = I18N[key] || key;
    if (arg !== undefined) s = s.replace(/%[sd]/, arg);
    return s;
  };

  // saveBlob hands a blob to the browser as a download. Batch members and the
  // zip are built in this tab and never exist as a server URL, so an object
  // URL is the only way to offer them.
  // renderPreviewInto builds the preview node for a decrypted blob and appends
  // it to box. Shared by the single-file landing page and the batch list so the
  // content-sniffing rules below cannot drift apart between the two.
  // Returns false when the blob refused to render.
  async function renderPreviewInto(box, kind, blob, name) {
    box.classList.add('dl-preview-' + kind);
    if (kind === 'text') {
      const pre = document.createElement('pre');
      pre.className = 'e2e-text';
      pre.textContent = await blob.text();
      box.appendChild(pre);
    } else if (kind === 'pdf') {
      // Only frame a blob that really is a PDF: a lying content type must not
      // turn into an HTML document on a blob: origin.
      const head = new Uint8Array(await blob.slice(0, 5).arrayBuffer());
      if (String.fromCharCode.apply(null, head) !== '%PDF-') return false;
      const frame = document.createElement('iframe');
      frame.src = URL.createObjectURL(blob);
      frame.title = name;
      box.appendChild(frame);
    } else {
      const el = document.createElement(
        kind === 'image' ? 'img' : kind === 'video' ? 'video' : 'audio');
      if (kind !== 'image') { el.controls = true; el.preload = 'metadata'; }
      el.src = URL.createObjectURL(blob);
      if (kind === 'image') el.alt = name;
      box.appendChild(el);
    }
    box.hidden = false;
    return true;
  }

  function saveBlob(blob, filename) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 30000);
  }

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

  // Binary units, matching the Go humanSize helper used in the templates.
  function fmtSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let v = Number(bytes) || 0;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return (i === 0 ? v : rateFmt.format(v)) + ' ' + units[i];
  }

  const fileCountLabel = (n) => (n === 1 ? t('batch.one_file') : t('batch.n_files', n));

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
      await renderPreviewInto(box, previewKind, blob, fileName);
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

  // ---- batch share landing (one link, many files) --------------------------
  //
  // Everything below happens in the tab. The server holds ciphertext and no
  // keys, so it cannot list, decrypt or zip anything: the page derives the
  // batch key from the fragment (or the password), unwraps each member's own
  // key, and assembles the zip locally.

  const batchRoot = document.getElementById('batch-root');
  if (batchRoot) {
    const E2E = window.KFS_E2E;
    const ZIP = window.KFS_ZIP;
    const batchId = batchRoot.getAttribute('data-batch');
    const mode = batchRoot.getAttribute('data-mode');
    const errBox = document.getElementById('batch-error');
    const keyMissing = document.getElementById('key-missing');
    const mainBox = document.getElementById('batch-main');
    const listEl = document.getElementById('batch-list');
    const zipBtn = document.getElementById('batch-zip');
    const summaryEl = document.getElementById('batch-summary');
    const progress = document.getElementById('batch-progress');
    const statusEl = document.getElementById('batch-status');
    const pctEl = document.getElementById('batch-pct');
    const fillEl = document.getElementById('batch-fill');

    let batchKey = null;
    let members = [];

    const fail = (msg) => {
      errBox.textContent = msg;
      errBox.hidden = false;
      progress.hidden = true;
    };
    const setProgress = (label, frac) => {
      progress.hidden = false;
      statusEl.textContent = label;
      const pct = Math.round(Math.max(0, Math.min(1, frac)) * 100);
      fillEl.style.width = pct + '%';
      pctEl.textContent = pct + '%';
    };
    const clearProgress = () => { progress.hidden = true; };

    async function loadManifest() {
      const res = await fetch('/b/' + batchId + '/manifest', {
        headers: { Accept: 'application/json' },
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      members = (await res.json()).files || [];
    }

    // Each member is sealed under its own key; the batch key only unwraps.
    //
    // The result is memoised per member: every /raw fetch counts as a download,
    // so previewing and then downloading the same file must not spend two.
    const plainCache = new Map();
    function decryptMember(m, onProgress) {
      if (plainCache.has(m.id)) return plainCache.get(m.id);
      const p = (async () => {
        const fileKey = await E2E.unwrapFileKey(batchKey, E2E.b64uDecode(m.wrappedKey));
        const res = await fetch('/b/' + batchId + '/f/' + m.id + '/raw');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const buf = await res.arrayBuffer();
        return E2E.decryptBuffer(buf, fileKey, m.contentType, onProgress);
      })();
      // A failed attempt must stay retryable, so only a success is kept.
      plainCache.set(m.id, p);
      p.catch(() => plainCache.delete(m.id));
      return p;
    }

    function renderList() {
      listEl.textContent = '';
      let total = 0;
      for (const m of members) total += Number(m.size) || 0;
      summaryEl.textContent = fileCountLabel(members.length) + ' · ' + fmtSize(total);
      zipBtn.hidden = members.length === 0;
      if (members.length === 0) {
        const li = document.createElement('li');
        li.className = 'batch-empty';
        li.textContent = t('batch_empty');
        listEl.appendChild(li);
        return;
      }
      for (const m of members) {
        const li = document.createElement('li');
        li.className = 'batch-row';

        const icon = document.createElement('span');
        icon.className = 'ficon ficon-' + (m.iconKind || 'generic');
        icon.setAttribute('aria-hidden', 'true');

        const meta = document.createElement('div');
        meta.className = 'batch-row-meta';
        const name = document.createElement('span');
        name.className = 'batch-row-name';
        name.textContent = m.name;
        const sub = document.createElement('span');
        sub.className = 'batch-row-sub muted';
        sub.textContent = fmtSize(m.size) + ' · ' + m.contentType;
        meta.appendChild(name);
        meta.appendChild(sub);

        const actions = document.createElement('div');
        actions.className = 'batch-row-actions';
        if (m.previewKind) {
          const pv = document.createElement('button');
          pv.type = 'button';
          pv.className = 'btn btn-ghost btn-sm';
          pv.textContent = t('batch_preview');
          pv.addEventListener('click', () => togglePreview(m, pv, li));
          actions.appendChild(pv);
        }
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-ghost btn-sm';
        btn.textContent = t('batch_download');
        btn.addEventListener('click', () => downloadMember(m, btn));
        actions.appendChild(btn);

        li.appendChild(icon);
        li.appendChild(meta);
        li.appendChild(actions);
        listEl.appendChild(li);
      }
    }

    async function togglePreview(m, btn, li) {
      const open = li.querySelector('.batch-preview');
      if (open) {
        open.remove();
        btn.textContent = t('batch_preview');
        return;
      }
      btn.disabled = true;
      errBox.hidden = true;
      try {
        setProgress(t('batch_fetching', m.name), 0);
        const blob = await decryptMember(m, (f) => setProgress(t('e2e_decrypting'), f));
        const box = document.createElement('div');
        box.className = 'dl-preview batch-preview';
        if (await renderPreviewInto(box, m.previewKind, blob, m.name)) {
          li.appendChild(box);
          btn.textContent = t('batch_hide_preview');
        } else {
          // A blob that failed its content check (a "PDF" that isn't one).
          fail(t('batch_preview_failed', m.name));
        }
      } catch (err) {
        fail(t('e2e_failed') + ' (' + err.message + ')');
      } finally {
        btn.disabled = false;
        clearProgress();
      }
    }

    async function downloadMember(m, btn) {
      btn.disabled = true;
      errBox.hidden = true;
      try {
        setProgress(t('batch_fetching', m.name), 0);
        const blob = await decryptMember(m, (f) => setProgress(t('e2e_decrypting'), f));
        saveBlob(blob, m.name);
      } catch (err) {
        fail(t('e2e_failed') + ' (' + err.message + ')');
      } finally {
        btn.disabled = false;
        clearProgress();
      }
    }

    zipBtn.addEventListener('click', async () => {
      zipBtn.disabled = true;
      errBox.hidden = true;
      try {
        // Members are decrypted one at a time and handed to the zip as blobs,
        // so only one file's plaintext is held as bytes at any moment.
        const entries = [];
        for (let i = 0; i < members.length; i++) {
          const m = members[i];
          setProgress(t('batch_fetching', m.name), i / members.length);
          entries.push({ name: m.name, blob: await decryptMember(m) });
        }
        const zip = await ZIP.build(entries, (done, all) =>
          setProgress(t('batch_zipping'), done / all));
        saveBlob(zip, t('batch_zip_name'));
      } catch (err) {
        fail(err && err.name === 'ZipTooLargeError'
          ? t('batch_zip_too_large')
          : t('e2e_failed') + ' (' + err.message + ')');
      } finally {
        zipBtn.disabled = false;
        clearProgress();
      }
    });

    async function startBatch() {
      mainBox.hidden = false;
      await loadManifest();
      renderList();
    }

    if (!E2E || !E2E.available || !ZIP) {
      fail(t('e2e_unsupported'));
      zipBtn.classList.add('btn-disabled');
    } else if (mode === 'url') {
      const secret = (location.hash || '').replace(/^#/, '');
      if (!/^[A-Za-z0-9_-]{43}$/.test(secret)) {
        keyMissing.hidden = false;
      } else {
        E2E.deriveBatchKey(E2E.b64uDecode(secret))
          .then((k) => { batchKey = k; return startBatch(); })
          .catch(() => fail(t('batch_failed')));
      }
    } else {
      const pwInput = document.getElementById('batch-password');
      const unlockBtn = document.getElementById('batch-unlock');
      const lockBox = document.getElementById('batch-lock');
      const salt = E2E.b64uDecode(batchRoot.getAttribute('data-salt') || '');
      const unlock = async () => {
        if (!pwInput.value) return;
        unlockBtn.disabled = true;
        errBox.hidden = true;
        try {
          setProgress(t('e2e_deriving'), 0.5);
          const { key, auth } = await E2E.derivePasswordKeys(pwInput.value, salt);
          const res = await fetch('/b/' + batchId + '/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'auth=' + encodeURIComponent(E2E.b64uEncode(auth)),
          });
          clearProgress();
          if (res.status === 429) { fail(t('rate_limited')); return; }
          if (!res.ok) { fail(t('e2e_wrong_pw')); pwInput.value = ''; return; }
          batchKey = key;
          lockBox.hidden = true;
          await startBatch();
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
    // One snapshot for the whole drop: a retry must repeat the share settings
    // the user actually chose, not whatever the form holds later on.
    const opts = snapshotOptions();
    for (const file of files) uploadOne(file, opts);
  }

  // snapshotOptions freezes the share settings for an upload. The form is
  // reset on pageshow and can be edited while transfers are still running, so
  // reading it again at retry time would silently change the share.
  function snapshotOptions() {
    const opts = { maxDownloads: '0', password: '' };
    if (expiresSel && expiresSel.value === 'custom' && expiresAtInput && expiresAtInput.value) {
      // datetime-local is timezone-less; convert to UTC ISO for the server
      opts.expiresAt = new Date(expiresAtInput.value).toISOString();
    } else if (expiresSel && expiresSel.value !== 'custom') {
      opts.expiresHours = expiresSel.value || '0';
    }
    if (maxDownloadsInput) opts.maxDownloads = maxDownloadsInput.value || '0';
    if (passwordInput) opts.password = passwordInput.value;
    return opts;
  }

  // Failure kinds a retry could plausibly clear. A file over the size limit,
  // an expired session or a browser without WebCrypto will fail identically
  // every time, so those rows get an explanation but no retry button.
  const RETRYABLE = {
    network: true, failed: true, quota: true, rate_limited: true,
    e2e_failed: true, cancelled: true,
  };

  function queueButton(labelKey, cls, onClick) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-ghost btn-sm ' + cls;
    b.textContent = t(labelKey);
    b.addEventListener('click', onClick);
    return b;
  }

  function newQueueRow(file) {
    const row = document.createElement('div');
    row.className = 'queue-item';
    row.innerHTML = `
      <div class="queue-info">
        <span class="queue-name"></span>
        <span class="queue-status">0%</span>
        <span class="queue-actions"></span>
      </div>
      <div class="queue-bar"><div class="queue-fill"></div></div>
      <p class="queue-reason" hidden></p>
    `;
    row.querySelector('.queue-name').textContent = file.name;
    queue.prepend(row);
    return row;
  }

  async function uploadOne(file, opts, existingRow) {
    const row = existingRow || newQueueRow(file);
    const fill = row.querySelector('.queue-fill');
    const status = row.querySelector('.queue-status');
    const actions = row.querySelector('.queue-actions');
    const reason = row.querySelector('.queue-reason');

    // A retry reuses the row, so clear whatever the previous attempt left.
    row.classList.remove('queue-error', 'queue-done', 'queue-cancelled');
    fill.style.width = '0%';
    status.textContent = '0%';
    actions.textContent = '';
    reason.textContent = '';
    reason.hidden = true;
    const staleLink = row.querySelector('.queue-link');
    if (staleLink) staleLink.remove();

    // Duck-typed AbortSignal: encryptFile only reads `.aborted`, and XHR has
    // its own abort(), so no AbortController is needed.
    const ctl = { aborted: false, xhr: null };

    function showRetry() {
      actions.textContent = '';
      actions.appendChild(queueButton('retry', 'btn-retry', () => uploadOne(file, opts, row)));
    }

    // The reason stays in the row until the upload is retried — a failure the
    // user stepped away from must still explain itself when they come back.
    function fail(kind, detail) {
      row.classList.add(kind === 'cancelled' ? 'queue-cancelled' : 'queue-error');
      status.textContent = t(kind);
      fill.style.width = kind === 'cancelled' ? '0%' : '100%';
      if (detail) {
        reason.textContent = detail;
        reason.hidden = false;
      }
      if (RETRYABLE[kind]) showRetry();
      else actions.textContent = '';
    }

    actions.appendChild(queueButton('cancel', 'btn-cancel', () => {
      if (ctl.aborted) return;
      ctl.aborted = true;
      if (ctl.xhr) ctl.xhr.abort();
      fail('cancelled', t('reason_cancelled'));
    }));

    // Expiry, limit and password belong to the batch row, not the member, so
    // the per-file POST carries none of them.
    const fd = new FormData();

    // Encrypt in this tab before anything is sent. The password (when set) is
    // never transmitted: only a token derived from it on a separate KDF
    // branch, which cannot yield the file key.
    const E2E = window.KFS_E2E;
    if (!E2E || !E2E.available) {
      // Fail closed. WebCrypto is missing precisely in insecure contexts
      // (plain HTTP), so falling back to a server-side upload would ship the
      // plaintext file and the password over the very connection that can't
      // be trusted — and would do it without telling anyone.
      fail('e2e_unavailable', t('e2e_insecure'));
      toast(t('e2e_insecure'));
      return;
    }

    let batch;
    try {
      status.textContent = t('e2e_deriving');
      batch = await ensureBatch(opts);
    } catch (err) {
      fail('failed', t('batch_failed'));
      return;
    }
    if (ctl.aborted) return;
    fd.append('batch_id', batch.id);

    try {
      // Every member gets its own random key, sealed under the batch key. The
      // server stores the sealed blob and can open neither.
      const rawKey = E2E.randomBytes(E2E.KEY_LEN);
      const key = await E2E.importAes(rawKey);
      fd.append('wrapped_key', E2E.b64uEncode(await E2E.wrapFileKey(batch.key, rawKey)));

      const cipher = await E2E.encryptFile(file, key, (f) => {
        fill.style.width = Math.round(f * 100) + '%';
        status.textContent = t('e2e_encrypting');
      }, ctl);
      fd.append('file', cipher, file.name);
      fd.append('e2e', '1');
      fd.append('plain_size', String(file.size));
      fd.append('content_type', file.type || 'application/octet-stream');
    } catch (err) {
      if (err && err.name === 'AbortError') return; // cancel handler already rendered
      fail('e2e_failed', t('reason_encrypt', (err && err.message) || String(err)));
      return;
    }
    if (ctl.aborted) return;

    const xhr = new XMLHttpRequest();
    ctl.xhr = xhr;
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
    // serverReason prefers the server's own message: httpError() sends only
    // http.StatusText, and the deliberate ones ("storage quota exceeded:
    // personal storage limit reached") say more than any generic string here.
    const serverReason = () => {
      const body = (xhr.responseText || '').trim();
      if (body && body.length <= 300 && body.charAt(0) !== '<') return body;
      return t('reason_http', xhr.status);
    };
    xhr.onload = () => {
      if (ctl.aborted) return;
      if (xhr.status >= 200 && xhr.status < 400) {
        fill.style.width = '100%';
        row.classList.add('queue-done');
        status.textContent = t('done');
        actions.textContent = '';
        // No per-file link: the batch link covers every file in this visit.
        batchState.count++;
        renderBatchPanel();
      } else if (xhr.status === 401) {
        fail('login', t('reason_login'));
        setTimeout(() => (location.href = '/login?next=/'), 800);
      } else if (xhr.status === 413) {
        fail('too_large', serverReason());
      } else if (xhr.status === 507) {
        fail('quota', serverReason());
      } else if (xhr.status === 429) {
        fail('rate_limited', serverReason());
      } else {
        fail('failed', serverReason());
      }
    };
    xhr.onerror = () => {
      if (ctl.aborted) return;
      fail('network', t('reason_network'));
    };
    xhr.send(fd);
  }

  // ---- batch link panel ----------------------------------------------------
  //
  // Every file uploaded during this visit lands under one link. The batch is
  // created lazily with the first file so the share options still apply, then
  // frozen: expiry, password and download limit live on the batch row, so
  // editing them afterwards would silently redefine a link that may already
  // have been sent to somebody. "Start a new link" is the way out.

  const batchState = { id: null, fragment: '', key: null, count: 0, creating: null };

  const batchShare = document.getElementById('batch-share');
  const batchShareUrl = document.getElementById('batch-share-url');
  const batchShareCopy = document.getElementById('batch-share-copy');
  const batchShareQR = document.getElementById('batch-share-qr');
  const batchShareLabel = document.getElementById('batch-share-label');
  const batchShareCount = document.getElementById('batch-share-count');
  const batchShareNote = document.getElementById('batch-share-note');
  const batchShareNew = document.getElementById('batch-share-new');

  function setOptionsLocked(locked) {
    for (const el of [expiresSel, expiresAtInput, passwordInput, maxDownloadsInput]) {
      if (el) el.disabled = locked;
    }
    const box = document.getElementById('options');
    if (box) box.classList.toggle('options-locked', locked);
  }

  // Concurrent uploads all await the same creation: handleFiles starts every
  // file at once, and without this they would each open their own batch.
  async function ensureBatch(opts) {
    if (batchState.id) return batchState;
    if (batchState.creating) return batchState.creating;

    const E2E = window.KFS_E2E;
    batchState.creating = (async () => {
      const body = new URLSearchParams();
      if (opts.expiresAt) body.set('expires_at', opts.expiresAt);
      else if (opts.expiresHours !== undefined) body.set('expires_hours', opts.expiresHours);
      body.set('max_downloads', opts.maxDownloads);

      let key;
      let fragment = '';
      if (opts.password) {
        const salt = E2E.randomBytes(E2E.SALT_LEN);
        const derived = await E2E.derivePasswordKeys(opts.password, salt);
        key = derived.key;
        body.set('auth_salt', E2E.b64uEncode(salt));
        body.set('auth_verifier', E2E.b64uEncode(derived.auth));
      } else {
        // The fragment is the only copy of the batch secret and never leaves
        // this tab — the server sees the batch id and nothing else.
        const secret = E2E.randomBytes(E2E.KEY_LEN);
        fragment = '#' + E2E.b64uEncode(secret);
        key = await E2E.deriveBatchKey(secret);
      }

      const res = await fetch('/batches', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: body.toString(),
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();

      batchState.id = data.id;
      batchState.fragment = fragment;
      batchState.key = key;
      setOptionsLocked(true);
      return batchState;
    })();

    try {
      return await batchState.creating;
    } finally {
      batchState.creating = null;
    }
  }

  function renderBatchPanel() {
    if (!batchShare || !batchState.id) return;
    const url = new URL('/b/' + batchState.id + batchState.fragment, location.href).toString();
    batchShare.hidden = false;
    batchShareLabel.textContent = t('batch_link');
    batchShareCount.textContent = fileCountLabel(batchState.count);
    batchShareUrl.value = url;
    batchShareCopy.textContent = t('copy');
    batchShareCopy.setAttribute('data-copy', url);
    batchShareQR.setAttribute('data-qr-url', url);
    batchShareNote.textContent = t('batch_options_locked');
    batchShareNew.textContent = t('batch_new');
  }

  if (batchShareUrl) {
    batchShareUrl.addEventListener('focus', () => batchShareUrl.select());
  }
  if (batchShareNew) {
    batchShareNew.addEventListener('click', () => {
      batchState.id = null;
      batchState.fragment = '';
      batchState.key = null;
      batchState.count = 0;
      batchState.creating = null;
      setOptionsLocked(false);
      batchShare.hidden = true;
      // The queue described the previous link; clearing avoids implying those
      // files are reachable through the next one.
      queue.textContent = '';
      if (sessionSection) sessionSection.hidden = true;
    });
  }
})();
