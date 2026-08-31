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
  // (which needs %d for counts) and this positional substitution.
  const t = (key, ...args) => {
    let s = I18N[key] || key;
    for (const arg of args) s = s.replace(/%[sd]/, arg);
    return s;
  };

  // ---- file-type icons -----------------------------------------------------
  //
  // Drawn from the sprite the page already carries (see "filesprite" in
  // _layout.html), so a list built here and one rendered by Go cannot drift
  // apart. Kinds must match iconKind() in handlers.go; anything unexpected
  // falls back to the generic page rather than rendering an empty box.
  const ICON_KINDS = ['image', 'video', 'audio', 'pdf', 'text', 'doc', 'archive', 'generic'];

  function fileIcon(kind) {
    const k = ICON_KINDS.indexOf(kind) >= 0 ? kind : 'generic';
    const span = document.createElement('span');
    span.className = 'ficon ficon-' + k;
    span.setAttribute('aria-hidden', 'true');
    span.innerHTML = '<svg class="ficon-svg" viewBox="0 0 24 24" width="20" height="20">' +
      '<use href="#fi-' + k + '"/></svg>';
    return span;
  }

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
      if (kind === 'image') {
        el.alt = name;
        makeZoomable(el, name);
      }
      box.appendChild(el);
    }
    box.hidden = false;
    return true;
  }

  // fetchWithProgress streams a response body and reports how much of it has
  // arrived, so a transfer says something before decryption begins. The length
  // it divides by is the ciphertext's — the only size the server knows — which
  // is fine: the fraction is the same for the plaintext.
  async function fetchWithProgress(url, onProgress) {
    const res = await fetch(url);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const total = Number(res.headers.get('Content-Length') || 0);
    const reader = res.body && res.body.getReader ? res.body.getReader() : null;
    if (!reader) return res.arrayBuffer();
    const parts = [];
    let got = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
      got += value.length;
      if (total && onProgress) onProgress(got / total);
    }
    return new Blob(parts).arrayBuffer();
  }

  // ---- click-to-enlarge ----------------------------------------------------
  //
  // The enlarged picture goes in FRONT of everything rather than growing
  // inside its own preview box. In the gallery that box is hemmed in by the
  // caption, the thumbnail strip and the arrow buttons, so enlarging in place
  // only ever meant "bigger, inside a small frame".
  //
  // The overlay is a <dialog> opened with showModal() because the gallery is
  // one too: a modal dialog lives in the browser's top layer, and nothing
  // painted in the ordinary page can be drawn above it — no z-index would
  // help. A second modal dialog stacks on top of the first, which is exactly
  // the foreground this needs.
  let zoomOverlay = null;

  function buildZoomOverlay() {
    const el = document.createElement('dialog');
    el.className = 'zoom';

    const img = document.createElement('img');
    img.className = 'zoom-img';
    // Clicking the picture puts it away again, the way clicking opened it.
    img.addEventListener('click', () => el.close());

    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'zoom-close';
    close.innerHTML =
      '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
    close.addEventListener('click', () => el.close());

    // The backdrop is the dialog itself; the image and button sit on top of it.
    // detail > 0 keeps a keyboard-activated button, which reports a click at
    // (0,0), from reading as a click on the backdrop.
    el.addEventListener('click', (e) => {
      if (e.target === el && e.detail > 0) el.close();
    });

    el.appendChild(img);
    el.appendChild(close);
    document.body.appendChild(el);
    zoomOverlay = { el: el, img: img, close: close };
  }

  function openZoom(src, name) {
    if (!zoomOverlay) buildZoomOverlay();
    zoomOverlay.img.src = src;
    zoomOverlay.img.alt = name || '';
    zoomOverlay.img.title = t('zoom_out');
    zoomOverlay.el.setAttribute('aria-label', name || t('zoom_in'));
    zoomOverlay.close.setAttribute('aria-label', t('gallery_close'));
    // A previous viewing may have been left panned into a corner.
    zoomOverlay.el.scrollTop = 0;
    zoomOverlay.el.scrollLeft = 0;
    zoomOverlay.el.showModal();
  }

  // makeZoomable marks a preview image as the thing that opens that overlay.
  //
  // It is not a <button> because a button cannot wrap an image without the
  // browser shrinking it to content width, so the role, the tab stop and the
  // Enter/Space handling are supplied here instead.
  function makeZoomable(img, name) {
    img.className = 'preview-zoom';
    img.tabIndex = 0;
    img.setAttribute('role', 'button');
    img.setAttribute('aria-haspopup', 'dialog');
    img.title = t('zoom_in');
    const open = () => openZoom(img.src, name);
    img.addEventListener('click', open);
    img.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); }
    });
  }

  // saveBlob hands a blob to the browser as a download. Batch members and the
  // zip are built in this tab and never exist as a server URL, so an object
  // URL is the only way to offer them.
  function saveBlob(blob, filename) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 30000);
  }

  // ---- keep the URL fragment across the language / theme switch ------------
  //
  // Those switchers are ordinary links to a server redirect. On a share page
  // the fragment is the decryption KEY, and a plain navigation drops it — so
  // switching language on /b/{id}#key landed the visitor on a keyless link and
  // the files became unopenable.
  //
  // The key cannot be carried in `next`: that is a query parameter and would
  // be sent to the server, which is the one thing this design never does.
  // Instead the fragment is re-attached to the switcher's own URL. A redirect
  // whose Location has no fragment inherits the request's (RFC 7231 §7.1.2),
  // so the browser restores it on arrival — and it is still never transmitted,
  // because browsers do not send fragments at all.
  if (location.hash.length > 1) {
    document.querySelectorAll('a[href^="/lang?"], a[href^="/theme?"]').forEach((a) => {
      a.setAttribute('href', a.getAttribute('href').split('#')[0] + location.hash);
    });
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

  // ---- end-to-end encrypted landing page ---------------------------------------
  // The ciphertext is fetched as-is and decrypted here; the plaintext never
  // exists outside this tab.

  const e2eRoot = document.getElementById('dl-root');
  if (e2eRoot && e2eRoot.getAttribute('data-e2e') === '1') {
    const E2E = window.PYXIS_E2E;
    const fileId = e2eRoot.getAttribute('data-file');
    const mode = e2eRoot.getAttribute('data-mode');
    const fileType = e2eRoot.getAttribute('data-type');
    const previewKind = e2eRoot.getAttribute('data-preview-kind');
    const errBox = document.getElementById('e2e-error');
    const warnBox = document.getElementById('e2e-warning');
    const keyMissing = document.getElementById('key-missing');
    const mainBox = document.getElementById('e2e-main');
    const dlBtn = document.getElementById('e2e-download');
    const progress = document.getElementById('e2e-progress');
    const statusEl = document.getElementById('e2e-status');
    const pctEl = document.getElementById('e2e-pct');
    const fillEl = document.getElementById('e2e-fill');

    // Container version and the authenticated manifest. Everything the page
    // shows before decryption came from the server's database columns, which
    // nothing binds to the ciphertext; after decryption the manifest is the
    // authority and any disagreement is reported rather than smoothed over.
    const e2eVersion = Number(e2eRoot.getAttribute('data-e2e-version')) || 1;
    const manifestAttr = e2eRoot.getAttribute('data-manifest') || '';
    const manifestBytes = manifestAttr ? E2E.b64uDecode(manifestAttr) : null;

    // The name used for the saved file. A version 4 share has none on the page
    // — the server holds only a sealed blob — so it starts as the placeholder
    // the template rendered and is replaced as soon as that blob is opened,
    // which needs no ciphertext at all. Older shares start with the server's
    // copy and swap it for the authenticated one after decryption.
    let fileName = e2eRoot.getAttribute('data-name') || '';
    const encNameAttr = e2eRoot.getAttribute('data-enc-name') || '';
    const manifestID = e2eRoot.getAttribute('data-manifest-id') || '';

    function showName(name) {
      fileName = name;
      const heading = document.querySelector('.dl-file-title h1');
      if (heading) heading.textContent = name;
      document.title = name + ' · Pyxis';
    }

    // Opening the sealed name is one short decryption, so it happens the moment
    // a key exists — before the file is fetched, and whether or not it ever is.
    async function openSealedName(nameKey) {
      if (!encNameAttr || !nameKey) return;
      try {
        const opened = await E2E.openName(nameKey, manifestID, E2E.b64uDecode(encNameAttr));
        showName(opened.name);
      } catch (err) {
        warn(t('name_unsealable'));
      }
    }

    let fileKey = null;
    let plainBlob = null;
    let inFlight = null;

    const fail = (msg) => {
      errBox.textContent = msg;
      errBox.hidden = false;
      progress.hidden = true;
    };
    const warn = (msg) => {
      if (!warnBox) return;
      warnBox.textContent = msg;
      warnBox.hidden = false;
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
        const buf = await fetchWithProgress('/files/' + fileId + '/raw',
          (f) => setProgress(t('e2e_downloading'), f));
        setProgress(t('e2e_decrypting'), 0);
        const onProgress = (f) => setProgress(t('e2e_decrypting'), f);
        // A version 2 share without its manifest cannot be authenticated at
        // all, so it is refused rather than quietly decrypted the old way —
        // "the metadata went missing" is exactly what a tampering server would
        // look like. Version 3 carries its own, so the server's copy is only
        // cross-checked against it.
        if (e2eVersion === 2 && !manifestBytes) throw new Error('missing manifest');
        const out = await E2E.openFile(
          e2eVersion, buf, fileKey, manifestBytes, fileType, onProgress);
        plainBlob = out.blob;
        if (out.manifest) adoptManifest(out.manifest);
        else warn(t('e2e_legacy'));
        progress.hidden = true;
        return plainBlob;
      })();
      return inFlight;
    }

    // adoptManifest switches the page over to the values the decryption just
    // authenticated. A mismatch is not fatal — the bytes are genuine either
    // way — but the recipient is told, because a file that arrives under a
    // different name than the sender gave it is worth knowing about.
    function adoptManifest(m) {
      // A version 4 manifest carries no name — that is the point of it — so
      // there is nothing here to disagree with the sealed one.
      if (!m || !m.name || m.name === fileName) return;
      warn(t('e2e_name_changed', fileName, m.name));
      showName(m.name);
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
        const raw = E2E.b64uDecode(secret);
        Promise.all([
          E2E.deriveUrlKey(raw, e2eVersion),
          encNameAttr ? E2E.deriveNameKey(raw, e2eVersion) : Promise.resolve(null),
        ])
          .then(async ([k, nk]) => {
            fileKey = k;
            await openSealedName(nk);
            return startSession();
          })
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
          const { key, auth, name: nameKey } = await E2E.derivePasswordKeys(pwInput.value, salt, e2eVersion);
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
          await openSealedName(nameKey);
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
    const E2E = window.PYXIS_E2E;
    const ZIP = window.PYXIS_ZIP;
    const batchId = batchRoot.getAttribute('data-batch');
    const mode = batchRoot.getAttribute('data-mode');
    const errBox = document.getElementById('batch-error');
    const warnBox = document.getElementById('batch-warning');
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
    let rosterKey = null;
    let nameKey = null;
    let batchVersion = 1;
    let members = [];

    const fail = (msg) => {
      errBox.textContent = msg;
      errBox.hidden = false;
      progress.hidden = true;
    };
    const warn = (msgs) => {
      if (!warnBox) return;
      const list = Array.isArray(msgs) ? msgs : [msgs];
      warnBox.textContent = list.join(' ');
      warnBox.hidden = list.length === 0;
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
      const data = await res.json();
      members = data.files || [];
      batchVersion = Number(data.e2eVersion) || 1;
      await openNames();
      await verifyRoster(data);
    }

    // From container version 4 the listing carries no names, only a sealed blob
    // per member. Opening them costs one AES-GCM decryption each — no
    // ciphertext is fetched and no download slot is spent — which is exactly
    // why the name is sealed apart from the file it belongs to.
    async function openNames() {
      for (const m of members) {
        if (m.name || !m.encName || !nameKey) continue;
        try {
          const opened = await E2E.openName(nameKey, m.manifestId, E2E.b64uDecode(m.encName));
          m.name = opened.name;
          // The type it was sealed with is authenticated; the column beside it
          // is not, so prefer the sealed one for what the page shows.
          if (opened.type) m.contentType = opened.type;
        } catch (err) {
          // A name that will not open under this link's key is a name this page
          // has no business guessing at.
          m.name = t('name_sealed');
          m.unverified = true;
        }
      }
    }

    // verifyRoster checks the listing the server just returned against the
    // sealed roster the uploader stored.
    //
    // Each member's own manifest proves that member's bytes and metadata; none
    // of them says anything about WHICH members belong to the link. That is the
    // server's answer, and without a roster it is unverifiable: a file can be
    // withheld, or one from elsewhere spliced in, and every remaining file still
    // decrypts flawlessly. So each served row is matched against a roster entry
    // by id, name, size, type and manifest digest.
    //
    // Findings are reported, not silently repaired. A missing file has a benign
    // explanation — the owner deleted it — and an extra one has a benign race:
    // a member uploaded moments ago, before its roster update landed. Neither
    // can be told apart from tampering here, so both are stated plainly and an
    // unverified member is kept out of "Download all".
    async function verifyRoster(data) {
      const notes = [];
      if (batchVersion < 2) {
        // A pre-version-2 batch never had a roster. Say so once rather than
        // implying a guarantee this link cannot give.
        warn([t('batch_legacy')]);
        return;
      }
      let roster;
      try {
        if (!data.roster) throw new Error('no roster');
        roster = await E2E.openRoster(rosterKey, batchId, E2E.b64uDecode(data.roster));
      } catch (err) {
        // Either the server has no roster for a batch that must have one, or it
        // does not open under this link's key. Both mean the member list is
        // unverifiable, which is the strongest statement this page can make.
        for (const m of members) m.unverified = true;
        warn([t('batch_no_roster')]);
        return;
      }

      const byID = new Map();
      for (const f of roster.files || []) byID.set(f.id, f);

      for (const m of members) {
        const entry = byID.get(m.id);
        if (!entry) {
          m.unverified = true;
          continue;
        }
        byID.delete(m.id);
        const digest = m.manifest ? await E2E.sha256b64u(E2E.b64uDecode(m.manifest)) : '';
        // Both names in this comparison are sealed under the same secret, from
        // two independent blobs: the roster the uploader wrote, and the name
        // blob stored beside the file. The server can produce neither.
        if (entry.manifest !== digest || entry.name !== m.name ||
            Number(entry.size) !== Number(m.size) || entry.type !== m.contentType) {
          m.unverified = true;
          continue;
        }
        // The manifest must also name THIS batch. Unwrapping the member's key
        // under another batch's key would already fail, so this cannot be the
        // only line of defence — but it turns "decryption failed" into a
        // statement about what actually went wrong.
        try {
          if (E2E.parseManifest(E2E.b64uDecode(m.manifest)).batch !== batchId) {
            m.unverified = true;
          }
        } catch (err) {
          m.unverified = true;
        }
      }

      const extra = members.filter((m) => m.unverified).length;
      if (extra > 0) notes.push(t('batch_unverified', extra));
      if (byID.size > 0) {
        notes.push(t('batch_missing', byID.size,
          Array.from(byID.values()).map((f) => f.name).join(', ')));
      }

      // Order is part of what the sender sealed. Matching the set of members
      // leaves the server free to rearrange them, which changes the order of a
      // "Download all" archive and the order they are read in — the roster
      // fixes the sequence, so check it rather than only the membership.
      if (notes.length === 0) {
        const servedOrder = members.map((m) => m.id).join(' ');
        const sealedOrder = (roster.files || []).map((f) => f.id).join(' ');
        if (servedOrder !== sealedOrder) {
          notes.push(t('batch_reordered'));
          // Restore the sealed order rather than only complaining about it.
          const pos = new Map((roster.files || []).map((f, i) => [f.id, i]));
          members.sort((a, b) => pos.get(a.id) - pos.get(b.id));
        }
      }
      warn(notes);
    }

    // Each member is sealed under its own key; the batch key only unwraps.
    //
    // The result is memoised per member: every /raw fetch counts as a download,
    // so previewing and then downloading the same file must not spend two.
    const plainCache = new Map();
    function decryptMember(m, onStage) {
      if (plainCache.has(m.id)) return plainCache.get(m.id);
      const stage = onStage || (() => {});
      const p = (async () => {
        const fileKey = await E2E.unwrapFileKey(batchKey, E2E.b64uDecode(m.wrappedKey));
        const buf = await fetchWithProgress('/b/' + batchId + '/f/' + m.id + '/raw',
          (f) => stage(t('e2e_downloading'), f));
        if (Number(m.e2eVersion) === 2 && !m.manifest) throw new Error('missing manifest');
        const out = await E2E.openFile(
          Number(m.e2eVersion), buf, fileKey,
          m.manifest ? E2E.b64uDecode(m.manifest) : null, m.contentType,
          (f) => stage(t('e2e_decrypting'), f));
        // The manifest is the authenticated name, so it wins over the row the
        // server sent — including for the file the browser then saves.
        if (out.manifest) m.name = out.manifest.name || m.name;
        return out.blob;
      })();
      // A failed attempt must stay retryable, so only a success is kept.
      plainCache.set(m.id, p);
      p.catch(() => plainCache.delete(m.id));
      return p;
    }

    // ---- per-file download buttons that show their own progress ------------
    //
    // The card's progress bar sits above the list, so the moment a preview is
    // open — which is exactly when a transfer is running — it has scrolled out
    // of sight. Each row therefore carries its own download button whose
    // background doubles as that file's progress bar, right under its name.
    const rowUI = new Map();

    function makeRowDownload(m) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-ghost btn-sm row-download';
      const fill = document.createElement('span');
      fill.className = 'row-download-fill';
      const label = document.createElement('span');
      label.className = 'row-download-label';
      label.textContent = t('batch_download');
      btn.appendChild(fill);
      btn.appendChild(label);
      btn.addEventListener('click', () => downloadMember(m, btn));
      rowUI.set(m.id, { btn: btn, fill: fill, label: label });
      return btn;
    }

    function setRowProgress(m, label, frac) {
      const ui = rowUI.get(m.id);
      if (!ui) return;
      const pct = Math.round(Math.max(0, Math.min(1, frac)) * 100);
      ui.btn.classList.add('is-busy');
      ui.btn.classList.remove('is-done');
      ui.fill.style.width = pct + '%';
      ui.label.textContent = label + ' ' + pct + '%';
    }

    // A finished transfer keeps a full bar instead of snapping back to empty:
    // a file that came down while its row was off-screen should still say so.
    function endRowProgress(m, ok) {
      const ui = rowUI.get(m.id);
      if (!ui) return;
      ui.btn.classList.remove('is-busy');
      ui.btn.classList.toggle('is-done', !!ok);
      ui.fill.style.width = ok ? '100%' : '0%';
      ui.label.textContent = t('batch_download');
    }

    // Progress goes to both places at once: the card's bar says what the page
    // as a whole is doing, the row's button says it where the file actually is.
    // Previewing a file decrypts it the same way a download does, so a preview
    // drives its row's button too.
    const report = (m) => (label, frac) => {
      setProgress(label, frac);
      setRowProgress(m, label, frac);
    };

    function renderList() {
      listEl.textContent = '';
      rowUI.clear();
      let total = 0;
      for (const m of members) total += Number(m.size) || 0;
      summaryEl.textContent = fileCountLabel(members.length) + ' · ' + fmtSize(total);
      zipBtn.hidden = members.length === 0;
      // Nothing to open a gallery on unless the server marked something
      // previewable, and an empty gallery is worse than no button.
      if (previewAllBtn) previewAllBtn.hidden = previewableMembers().length === 0;
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

        const icon = fileIcon(m.iconKind);

        const meta = document.createElement('div');
        meta.className = 'batch-row-meta';
        const name = document.createElement('span');
        name.className = 'batch-row-name';
        name.textContent = m.name;
        // Wide screens still ellipse these two lines; the title keeps the full
        // value reachable there (narrow screens wrap instead of truncating).
        name.title = m.name;
        const sub = document.createElement('span');
        sub.className = 'batch-row-sub muted';
        sub.textContent = fmtSize(m.size) + ' · ' + m.contentType;
        sub.title = sub.textContent;
        meta.appendChild(name);
        meta.appendChild(sub);
        if (m.unverified) {
          // The row is still downloadable — its own manifest still has to
          // authenticate its bytes — but nothing vouches for it belonging to
          // this link, and the badge says exactly that.
          const badge = document.createElement('span');
          badge.className = 'batch-row-warn';
          badge.textContent = t('batch_row_unverified');
          badge.title = t('batch_row_unverified_hint');
          meta.appendChild(badge);
        }
        meta.appendChild(makeRowDownload(m));

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

        li.appendChild(icon);
        li.appendChild(meta);
        if (actions.childNodes.length > 0) li.appendChild(actions);
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
        setRowProgress(m, t('e2e_downloading'), 0);
        const blob = await decryptMember(m, report(m));
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
        // Back to idle, not to "done": the bytes are decrypted and cached, but
        // nothing was saved, and a green full bar on a Download button would
        // say otherwise.
        endRowProgress(m, false);
        clearProgress();
      }
    }

    async function downloadMember(m, btn) {
      btn.disabled = true;
      errBox.hidden = true;
      let ok = false;
      try {
        setProgress(t('batch_fetching', m.name), 0);
        setRowProgress(m, t('e2e_downloading'), 0);
        const blob = await decryptMember(m, report(m));
        ok = true;
        saveBlob(blob, m.name);
      } catch (err) {
        fail(t('e2e_failed') + ' (' + err.message + ')');
      } finally {
        btn.disabled = false;
        endRowProgress(m, ok);
        clearProgress();
      }
    }

    // ---- "Preview all" gallery ---------------------------------------------
    //
    // One large stage over a grid strip of every previewable member, with
    // arrow buttons and arrow keys to step through them.
    //
    // Files are decrypted ONLY as they are stepped onto, never the whole set up
    // front: a /raw fetch is exactly what a batch's download limit counts, and
    // opening a gallery must not spend the allowance on files nobody looked at.
    // Anything already fetched comes back from plainCache for free, so a file
    // previewed here and then downloaded still costs one.
    //
    // It is a <dialog> opened with showModal() rather than a hand-rolled
    // overlay: that gives the focus trap, Escape, the backdrop and the top
    // layer for nothing, and this is the one place on the page where focus
    // must not wander off behind the modal.

    const previewableMembers = () => members.filter((m) => m.previewKind);

    // Files at or below this are fetched and decrypted as soon as the gallery
    // opens, so stepping through a set of ordinary photos does not stall on
    // every arrow press. The threshold is per file, not for the set: a share of
    // three snapshots and one long video should load the snapshots up front and
    // still leave the video until somebody actually reaches it.
    const PREFETCH_MAX = 10 * 1024 * 1024; // 10 MiB

    // Prefetches run a few at a time rather than genuinely all at once. They
    // share one connection either way, so firing twenty in parallel makes each
    // of them slower without finishing the set any sooner — and the file on the
    // stage is the one somebody is actually waiting for.
    const PREFETCH_PARALLEL = 3;

    const previewAllBtn = document.getElementById('batch-preview-all');
    let gallery = null;          // built on first open, then reused
    let galleryItems = [];
    let galleryIndex = 0;
    let gallerySeq = 0;          // guards a decrypt the user has stepped past
    const galleryNodes = new Map(); // member id -> rendered preview element
    const galleryTiles = new Map(); // member id -> its strip tile

    const CHEVRON = {
      prev: 'M15 5l-7 7 7 7',
      next: 'M9 5l7 7-7 7',
    };

    function buildGallery() {
      const el = document.createElement('dialog');
      el.className = 'gallery';
      el.setAttribute('aria-label', t('preview_all'));

      // Everything lives in an inner box so the dialog element itself is only
      // ever the backdrop — which is what makes the click-outside check below
      // a simple target comparison.
      const box = document.createElement('div');
      box.className = 'gallery-box';

      const head = document.createElement('div');
      head.className = 'gallery-head';
      const title = document.createElement('h2');
      title.className = 'gallery-title';
      title.textContent = t('preview_all');
      const close = document.createElement('button');
      close.type = 'button';
      close.className = 'btn btn-ghost btn-sm gallery-close';
      close.setAttribute('aria-label', t('gallery_close'));
      close.innerHTML =
        '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
      close.addEventListener('click', () => el.close());
      head.appendChild(title);
      head.appendChild(close);

      const navButton = (kind, delta) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'gallery-nav';
        b.setAttribute('aria-label', t(kind === 'prev' ? 'gallery_prev' : 'gallery_next'));
        b.innerHTML =
          '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" ' +
          'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="' +
          CHEVRON[kind] + '"/></svg>';
        b.addEventListener('click', () => step(delta));
        return b;
      };

      const stage = document.createElement('div');
      stage.className = 'gallery-stage';
      const view = document.createElement('div');
      view.className = 'gallery-view';
      stage.appendChild(navButton('prev', -1));
      stage.appendChild(view);
      stage.appendChild(navButton('next', 1));

      const caption = document.createElement('div');
      caption.className = 'gallery-caption';
      const name = document.createElement('span');
      name.className = 'gallery-name';
      const warn = document.createElement('span');
      warn.className = 'batch-row-warn gallery-warn';
      warn.textContent = t('batch_row_unverified');
      warn.title = t('batch_row_unverified_hint');
      warn.hidden = true;
      const counter = document.createElement('span');
      counter.className = 'gallery-counter';
      caption.appendChild(name);
      caption.appendChild(warn);
      caption.appendChild(counter);

      const progress = document.createElement('div');
      progress.className = 'queue-item gallery-progress';
      progress.hidden = true;
      progress.innerHTML =
        '<div class="queue-info"><span class="queue-name"></span>' +
        '<span class="queue-status"></span></div>' +
        '<div class="queue-bar"><div class="queue-fill"></div></div>';

      const err = document.createElement('p');
      err.className = 'alert gallery-error';
      err.hidden = true;

      const strip = document.createElement('ul');
      strip.className = 'gallery-strip';

      const note = document.createElement('p');
      note.className = 'gallery-note muted';
      const lines = [t('gallery_hint'), t('gallery_prefetch', fmtSize(PREFETCH_MAX))];
      // Opening the gallery now spends a download on every small file at once,
      // so a link that is counting them has to say so before that happens.
      if (batchRoot.getAttribute('data-limited') === '1') lines.push(t('gallery_limit_note'));
      note.textContent = lines.join(' ');

      box.appendChild(head);
      box.appendChild(stage);
      box.appendChild(caption);
      box.appendChild(progress);
      box.appendChild(err);
      box.appendChild(strip);
      box.appendChild(note);
      el.appendChild(box);

      el.addEventListener('keydown', onGalleryKey);
      // Leaving a video or audio file playing behind a closed dialog is the
      // one thing a gallery must never do.
      el.addEventListener('close', () => pauseMedia(gallery.view));
      // detail > 0 keeps a keyboard-activated button, which reports a click at
      // (0,0) on the dialog, from reading as a click on the backdrop.
      el.addEventListener('click', (e) => {
        if (e.target === el && e.detail > 0) el.close();
      });

      document.body.appendChild(el);
      gallery = {
        el: el, view: view, name: name, warn: warn, counter: counter,
        strip: strip, err: err, progress: progress,
        pStatus: progress.querySelector('.queue-name'),
        pPct: progress.querySelector('.queue-status'),
        pFill: progress.querySelector('.queue-fill'),
      };
    }

    function onGalleryKey(e) {
      const tag = e.target && e.target.tagName;
      // A focused player keeps its own arrow-key seeking, and a text field its
      // caret; stealing those would be worse than not having the shortcut.
      if (tag === 'VIDEO' || tag === 'AUDIO' || tag === 'INPUT' || tag === 'TEXTAREA') return;
      if (e.key === 'ArrowRight') { e.preventDefault(); step(1); }
      else if (e.key === 'ArrowLeft') { e.preventDefault(); step(-1); }
      else if (e.key === 'Home') { e.preventDefault(); showGalleryItem(0); }
      else if (e.key === 'End') { e.preventDefault(); showGalleryItem(galleryItems.length - 1); }
    }

    function step(delta) {
      if (galleryItems.length > 0) showGalleryItem(galleryIndex + delta);
    }

    function pauseMedia(root) {
      if (root) root.querySelectorAll('video, audio').forEach((el) => el.pause());
    }

    function setGalleryProgress(label, frac) {
      gallery.progress.hidden = false;
      gallery.pStatus.textContent = label;
      const pct = Math.round(Math.max(0, Math.min(1, frac)) * 100);
      gallery.pFill.style.width = pct + '%';
      gallery.pPct.textContent = pct + '%';
    }

    function renderStrip() {
      gallery.strip.textContent = '';
      galleryTiles.clear();
      galleryItems.forEach((m, i) => {
        const li = document.createElement('li');
        const tile = document.createElement('button');
        tile.type = 'button';
        tile.className = 'gallery-tile';
        tile.setAttribute('aria-label', t('gallery_show', m.name));

        const thumb = document.createElement('span');
        thumb.className = 'gallery-thumb';
        thumb.appendChild(fileIcon(m.iconKind));
        const cap = document.createElement('span');
        cap.className = 'gallery-tile-name';
        cap.textContent = m.name;
        cap.title = m.name;

        tile.appendChild(thumb);
        tile.appendChild(cap);
        tile.addEventListener('click', () => showGalleryItem(i));
        li.appendChild(tile);
        gallery.strip.appendChild(li);
        galleryTiles.set(m.id, { tile: tile, thumb: thumb });

        // A tile whose file was already decrypted earlier in this session —
        // through a row preview or download — can show its picture right away.
        const cached = plainCache.get(m.id);
        if (cached) cached.then((blob) => setTileThumb(m, blob)).catch(() => {});
      });
    }

    function markStrip() {
      for (const [id, ui] of galleryTiles) {
        const current = galleryItems[galleryIndex] && galleryItems[galleryIndex].id === id;
        if (current) {
          ui.tile.setAttribute('aria-current', 'true');
          ui.tile.scrollIntoView({ block: 'nearest', inline: 'nearest' });
        } else {
          ui.tile.removeAttribute('aria-current');
        }
      }
    }

    function setTileBusy(m, busy) {
      const ui = galleryTiles.get(m.id);
      if (ui) ui.tile.classList.toggle('is-loading', busy);
    }

    // prefetchGallery pulls down everything small enough, in the background,
    // starting after the file on the stage has claimed the connection.
    //
    // decryptMember is memoised, so a file already fetched — by the stage, by a
    // row preview, by a download — is skipped here and never costs a second
    // request against the link's download limit.
    function prefetchGallery() {
      const queue = galleryItems.filter(
        (m) => Number(m.size) <= PREFETCH_MAX && !plainCache.has(m.id));
      let next = 0;
      const pump = async () => {
        while (next < queue.length) {
          // Closing the gallery stops the queue where it is. What is already in
          // flight is paid for, but nothing new is started for a gallery
          // nobody is looking at any more.
          if (!gallery.el.open) return;
          const m = queue[next++];
          setTileBusy(m, true);
          try {
            const blob = await decryptMember(m, (label, f) => setRowProgress(m, label, f));
            setTileThumb(m, blob);
          } catch (err) {
            // Deliberately silent. plainCache drops a failed attempt, so
            // stepping onto this file tries again and reports the failure
            // there — next to the file, where it means something — rather than
            // as an alert about a file nobody has looked at yet.
          } finally {
            setTileBusy(m, false);
            endRowProgress(m, false);
          }
        }
      };
      for (let i = 0; i < Math.min(PREFETCH_PARALLEL, queue.length); i++) pump();
    }

    // Only images: a still from a video would mean decoding the video, which
    // is work nobody asked for.
    function setTileThumb(m, blob) {
      const ui = galleryTiles.get(m.id);
      // The guard looks for an existing <img>, not for any child: the tile
      // always starts with a file-type icon in it.
      if (!ui || m.previewKind !== 'image' || ui.thumb.querySelector('img')) return;
      const img = document.createElement('img');
      img.src = URL.createObjectURL(blob);
      img.alt = '';
      ui.thumb.textContent = '';
      ui.thumb.appendChild(img);
    }

    async function showGalleryItem(i) {
      const n = galleryItems.length;
      if (n === 0) return;
      // Wraps in both directions, so → off the end lands on the first file
      // rather than on a dead button.
      galleryIndex = ((i % n) + n) % n;
      const m = galleryItems[galleryIndex];
      const seq = ++gallerySeq;

      pauseMedia(gallery.view);
      gallery.view.textContent = '';
      gallery.name.textContent = m.name;
      gallery.counter.textContent = (galleryIndex + 1) + ' / ' + n;
      gallery.warn.hidden = !m.unverified;
      gallery.err.hidden = true;
      markStrip();

      const cached = galleryNodes.get(m.id);
      if (cached) {
        gallery.view.appendChild(cached);
        return;
      }

      setGalleryProgress(t('e2e_downloading'), 0);
      try {
        const blob = await decryptMember(m, (label, f) => {
          if (seq === gallerySeq) setGalleryProgress(label, f);
          setRowProgress(m, label, f);
        });
        if (seq !== gallerySeq) return; // the user stepped on while this ran
        const box = document.createElement('div');
        box.className = 'dl-preview gallery-preview';
        if (!(await renderPreviewInto(box, m.previewKind, blob, m.name))) {
          // A blob that failed its content check (a "PDF" that isn't one).
          throw new Error(t('batch_preview_failed', m.name));
        }
        if (seq !== gallerySeq) return;
        galleryNodes.set(m.id, box);
        setTileThumb(m, blob);
        gallery.view.textContent = '';
        gallery.view.appendChild(box);
      } catch (err) {
        if (seq !== gallerySeq) return;
        gallery.err.textContent = t('e2e_failed') + ' (' + err.message + ')';
        gallery.err.hidden = false;
      } finally {
        if (seq === gallerySeq) gallery.progress.hidden = true;
        endRowProgress(m, false);
      }
    }

    if (previewAllBtn) {
      previewAllBtn.addEventListener('click', () => {
        galleryItems = previewableMembers();
        if (galleryItems.length === 0) {
          fail(t('gallery_nothing'));
          return;
        }
        if (!gallery) buildGallery();
        renderStrip();
        gallery.el.showModal();
        // The stage goes first so its request is the one already in flight when
        // the prefetch queue starts; decryptMember has it in plainCache by the
        // time showGalleryItem yields, so the prefetch skips it.
        showGalleryItem(0);
        prefetchGallery();
      });
    }

    zipBtn.addEventListener('click', async () => {
      zipBtn.disabled = true;
      errBox.hidden = true;
      try {
        // Members are decrypted one at a time and handed to the zip as blobs,
        // so only one file's plaintext is held as bytes at any moment.
        //
        // Unverified members are left out: the archive is a single artefact the
        // recipient will treat as "the share", and a file nothing ties to this
        // link must not ride into it unnoticed. They stay individually
        // downloadable, where the badge is right next to the button.
        const included = members.filter((m) => !m.unverified);
        const entries = [];
        for (let i = 0; i < included.length; i++) {
          const m = included[i];
          setProgress(t('batch_fetching', m.name), i / included.length);
          setRowProgress(m, t('e2e_downloading'), 0);
          // Read the name AFTER decrypting: that is when the manifest's
          // authenticated name replaces the server's, and an object literal
          // would otherwise capture the old one before the await resolves.
          // Row progress is driven per file so the list shows how far the
          // archive has got even when the card's bar is scrolled away.
          const blob = await decryptMember(m, (label, f) => setRowProgress(m, label, f));
          endRowProgress(m, true);
          entries.push({ name: m.name, blob: blob });
        }
        if (entries.length === 0) throw new Error(t('batch_empty'));
        const zip = await ZIP.build(entries, (done, all) =>
          setProgress(t('batch_zipping'), done / all));
        saveBlob(zip, t('batch_zip_name'));
      } catch (err) {
        fail(err && err.name === 'ZipTooLargeError'
          ? t('batch_zip_too_large')
          : t('e2e_failed') + ' (' + err.message + ')');
        // The member that threw is still showing a half-filled bar; nothing
        // else will clear it, and a stuck progress bar reads as "still going".
        for (const m of members) {
          const ui = rowUI.get(m.id);
          if (ui && ui.btn.classList.contains('is-busy')) endRowProgress(m, false);
        }
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
        E2E.deriveBatchKeys(E2E.b64uDecode(secret), E2E.VERSION)
          .then((k) => {
            batchKey = k.key;
            rosterKey = k.roster;
            nameKey = k.name;
            return startBatch();
          })
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
          const derived = await E2E.derivePasswordKeys(pwInput.value, salt, E2E.VERSION);
          const res = await fetch('/b/' + batchId + '/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'auth=' + encodeURIComponent(E2E.b64uEncode(derived.auth)),
          });
          clearProgress();
          if (res.status === 429) { fail(t('rate_limited')); return; }
          if (!res.ok) { fail(t('e2e_wrong_pw')); pwInput.value = ''; return; }
          batchKey = derived.key;
          rosterKey = derived.roster;
          nameKey = derived.name;
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

  // Delegated rather than bound per form at load: the bulk-delete form's
  // message carries the number of selected files, so its data-confirm is
  // rewritten as the selection changes and cannot be read once up front.
  document.addEventListener('submit', (e) => {
    const form = e.target.closest && e.target.closest('form[data-confirm]');
    if (!form) return;
    if (!confirm(form.getAttribute('data-confirm'))) {
      e.preventDefault();
      return;
    }
    // A deleted file's remembered name is dead weight; drop it as it goes.
    if (form.id === 'bulk-delete') {
      forgetNames(Array.from(form.querySelectorAll('input[name="id"]:checked'), (b) => b.value));
    } else if (form.classList.contains('file-delete')) {
      const li = form.closest('.file-item');
      if (li) forgetNames([li.getAttribute('data-id')]);
    }
  });

  // ---- names this browser remembers -------------------------------------------
  //
  // A version 4 name is sealed under the key in the share link, so the file
  // list — which has no link and no key — genuinely cannot read it. That is the
  // point, but it would leave the owner's own file manager showing a column of
  // "Encrypted file name".
  //
  // So the browser that uploaded a file keeps the name it already knew, here,
  // for its own lists. It never leaves this device, it is not a key, and losing
  // it costs nothing but the label: another browser shows the placeholder, and
  // the file itself is unaffected either way.
  const NAME_STORE = 'pyxis_names';
  const NAME_STORE_MAX = 2000;

  function readNameStore() {
    try {
      const raw = localStorage.getItem(NAME_STORE);
      const parsed = raw ? JSON.parse(raw) : null;
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (e) {
      return {}; // private mode, blocked storage, corrupted value — all the same here
    }
  }

  function rememberName(id, name) {
    if (!id || !name) return;
    try {
      const store = readNameStore();
      store[id] = name;
      const ids = Object.keys(store);
      // Oldest first: JSON objects keep insertion order for string keys, so
      // trimming the front drops what was learned longest ago.
      if (ids.length > NAME_STORE_MAX) {
        for (const old of ids.slice(0, ids.length - NAME_STORE_MAX)) delete store[old];
      }
      localStorage.setItem(NAME_STORE, JSON.stringify(store));
    } catch (e) { /* a name we cannot remember is not worth an error */ }
  }

  function forgetNames(ids) {
    if (!ids || !ids.length) return;
    try {
      const store = readNameStore();
      for (const id of ids) delete store[id];
      localStorage.setItem(NAME_STORE, JSON.stringify(store));
    } catch (e) { /* nothing to do */ }
  }

  // Fills sealed rows in with what this browser remembers. The row keeps saying
  // where the name came from, because a remembered name is not an authenticated
  // one: nothing here has verified it against the file.
  function applyRememberedNames(root) {
    const rows = (root || document).querySelectorAll('.file-name-sealed');
    if (!rows.length) return;
    const store = readNameStore();
    for (const el of rows) {
      const li = el.closest('.file-item');
      const name = li && store[li.getAttribute('data-id')];
      if (!name) continue;
      el.textContent = name;
      el.classList.remove('file-name-sealed');
      el.classList.add('file-name-remembered');
      el.title = t('files.name_remembered');
      // The filter searches what the row says, so it has to know too.
      li.setAttribute('data-search',
        (li.getAttribute('data-search') || '') + ' ' + name);
      const form = li.querySelector('.file-delete');
      if (form) form.setAttribute('data-confirm', t('confirm_delete', name));
      const box = li.querySelector('.file-select input[type="checkbox"]');
      if (box) box.setAttribute('aria-label', name);
    }
  }
  applyRememberedNames();

  // ---- history page: batch groups ---------------------------------------------
  //
  // Files uploaded in one visit share a link, an expiry and a download counter,
  // so the server nests them under one group header. Folding is a class on the
  // group, deliberately not the `hidden` property the search uses: a folded
  // member is still in the list, and "select all" has to keep meaning every row
  // the filter left there, folded or not.

  const fileList = document.getElementById('file-list');
  const groups = () =>
    fileList ? Array.from(fileList.querySelectorAll('.file-group')) : [];

  function setFolded(group, folded) {
    group.classList.toggle('group-collapsed', folded);
    const toggle = group.querySelector('.group-toggle');
    if (toggle) toggle.setAttribute('aria-expanded', folded ? 'false' : 'true');
  }

  if (fileList) {
    fileList.addEventListener('click', (e) => {
      const head = e.target.closest && e.target.closest('.group-head');
      if (!head) return;
      // The whole header folds the group, except where it already carries a
      // control of its own: the checkbox, the batch link, copy/QR/open.
      if (e.target.closest('a, label, input, button:not(.group-toggle)')) return;
      const group = head.closest('.file-group');
      setFolded(group, !group.classList.contains('group-collapsed'));
    });

    const expandAll = document.getElementById('expand-all');
    const collapseAll = document.getElementById('collapse-all');
    if (expandAll) {
      expandAll.addEventListener('click', () => {
        for (const g of groups()) setFolded(g, false);
      });
    }
    if (collapseAll) {
      collapseAll.addEventListener('click', () => {
        for (const g of groups()) setFolded(g, true);
      });
    }
  }

  // ---- history page: live search ----------------------------------------------

  const search = document.getElementById('file-search');
  // Set by the multi-select block below, which has to react to rows being
  // filtered away; declared here because the search handler runs first.
  let onListFiltered = () => {};
  if (search && fileList) {
    const noResults = document.getElementById('no-results');
    // A match inside a folded group would otherwise stay invisible, so a live
    // query opens every group that has one. The fold the user chose is put back
    // when the query is cleared.
    let foldMemory = null;
    search.addEventListener('input', () => {
      const q = search.value.trim().toLowerCase();
      let visible = 0;
      fileList.querySelectorAll('.file-item').forEach((li) => {
        const hit = !q || (li.getAttribute('data-search') || '').toLowerCase().includes(q);
        li.hidden = !hit;
        if (hit) visible++;
      });
      const all = groups();
      if (q && !foldMemory) {
        foldMemory = new Map(all.map((g) => [g, g.classList.contains('group-collapsed')]));
      }
      for (const g of all) {
        // A group whose every member was filtered away goes with them: its
        // header would otherwise advertise files the list is not showing.
        g.hidden = g.querySelectorAll('.file-item:not([hidden])').length === 0;
        if (q) setFolded(g, false);
      }
      if (!q && foldMemory) {
        for (const [g, folded] of foldMemory) setFolded(g, folded);
        foldMemory = null;
      }
      if (noResults) noResults.hidden = visible > 0;
      onListFiltered();
    });
  }

  // ---- history page: multi-select + bulk delete --------------------------------
  //
  // The checkboxes sit in the list items but belong to the bulk form via their
  // form="" attribute, so the page needs no wrapper form around the list — one
  // would have to contain the per-row delete forms, which HTML forbids.

  const bulkForm = document.getElementById('bulk-delete');
  if (bulkForm && fileList) {
    const bulkAll = document.getElementById('bulk-all');
    const bulkCount = document.getElementById('bulk-count');
    const bulkBtn = document.getElementById('bulk-delete-btn');
    const emptyLabel = bulkCount.textContent;
    let anchor = null; // last box clicked, for shift-range selection

    // A group header's checkbox drives its members and submits nothing itself,
    // so it never counts as a selectable row.
    const ROW_BOX = '.file-select input[type="checkbox"]:not(.group-select)';
    const boxes = () => Array.from(fileList.querySelectorAll(ROW_BOX));
    // Only rows the search leaves visible take part: "select all" has to mean
    // what the list is showing, not what it would show unfiltered.
    const visibleBoxes = () => boxes().filter((b) => !b.closest('.file-item').hidden);
    const groupBoxes = (group) =>
      Array.from(group.querySelectorAll(ROW_BOX)).filter((b) => !b.closest('.file-item').hidden);

    if (boxes().length === 0) bulkForm.hidden = true;

    function sync() {
      const all = visibleBoxes();
      const picked = all.filter((b) => b.checked);
      bulkBtn.disabled = picked.length === 0;
      bulkCount.textContent = picked.length === 0 ? emptyLabel : t('selected', picked.length);
      bulkForm.setAttribute('data-confirm', t('confirm_delete_many', picked.length));
      bulkAll.checked = all.length > 0 && picked.length === all.length;
      bulkAll.indeterminate = picked.length > 0 && picked.length < all.length;
      for (const g of groups()) {
        const gb = g.querySelector('.group-select');
        if (!gb) continue;
        const mine = groupBoxes(g);
        const on = mine.filter((b) => b.checked).length;
        gb.checked = mine.length > 0 && on === mine.length;
        gb.indeterminate = on > 0 && on < mine.length;
      }
    }

    bulkAll.addEventListener('change', () => {
      for (const b of visibleBoxes()) b.checked = bulkAll.checked;
      anchor = null;
      sync();
    });

    fileList.addEventListener('click', (e) => {
      const box = e.target.closest && e.target.closest(ROW_BOX);
      if (!box) return;
      const all = visibleBoxes();
      const from = anchor ? all.indexOf(anchor) : -1;
      const to = all.indexOf(box);
      if (e.shiftKey && from >= 0 && to >= 0 && from !== to) {
        const lo = Math.min(from, to);
        const hi = Math.max(from, to);
        for (let i = lo; i <= hi; i++) all[i].checked = box.checked;
      }
      anchor = box;
    });
    // The count is driven by `change` rather than the click above so it is
    // right no matter how a box was toggled — label click, keyboard, or shift.
    fileList.addEventListener('change', (e) => {
      const gb = e.target.closest && e.target.closest('.group-select');
      if (gb) {
        for (const b of groupBoxes(gb.closest('.file-group'))) b.checked = gb.checked;
        anchor = null;
      }
      sync();
    });

    // A row hidden by the search must not stay selected: it would be deleted
    // by a button whose count never mentioned it.
    onListFiltered = () => {
      for (const b of boxes()) {
        if (b.closest('.file-item').hidden) b.checked = false;
      }
      sync();
    };

    sync();
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
  const optionsBox = document.getElementById('options');
  const singleUseBtn = document.getElementById('opt-single-use');
  // 0 means "no limit advertised", in which case only the server decides.
  const MAX_UPLOAD = Number(form.getAttribute('data-max-upload')) || 0;

  const stepParams = document.getElementById('step-params');
  const stepFiles = document.getElementById('step-files');
  const stepConfirm = document.getElementById('opt-confirm');
  const stepEdit = document.getElementById('step-edit');
  const step1Chip = document.getElementById('step1-chip');
  const step2Sub = document.getElementById('step2-sub');

  // Three independent reasons the share options can be read-only: step 1 has
  // been confirmed, the batch link has been created and its terms are frozen,
  // or Single-Use is driving them. All are folded into applyOptionState so none
  // can re-enable a field another still wants disabled — declared before
  // resetOptions() runs, which calls it.
  let optionsLocked = false;
  let paramsConfirmed = false;
  let singleUse = false;
  let preSingleUse = null;

  function applyOptionState() {
    const frozen = optionsLocked || paramsConfirmed;
    for (const el of [expiresSel, expiresAtInput, passwordInput, maxDownloadsInput]) {
      if (el) el.disabled = frozen;
    }
    // Single-Use owns expiry and the download limit; the password stays free.
    if (!frozen && singleUse) {
      for (const el of [expiresSel, expiresAtInput, maxDownloadsInput]) {
        if (el) el.disabled = true;
      }
    }
    if (optionsBox) optionsBox.classList.toggle('options-locked', frozen);
    if (singleUseBtn) {
      singleUseBtn.disabled = frozen;
      singleUseBtn.setAttribute('aria-pressed', singleUse ? 'true' : 'false');
    }
  }

  // The gate between the two steps. Step 2 is inert until step 1 is confirmed:
  // the file input is disabled, so neither a click nor a keyboard activation of
  // the dropzone label opens a picker, and handleFiles turns a drop away on its
  // own — the styling only describes a state the DOM already enforces.
  function applyStepState() {
    if (stepFiles) {
      stepFiles.classList.toggle('step-locked', !paramsConfirmed);
      stepFiles.setAttribute('aria-disabled', paramsConfirmed ? 'false' : 'true');
    }
    if (fileInput) fileInput.disabled = !paramsConfirmed;
    if (stepParams) stepParams.classList.toggle('step-done', paramsConfirmed);
    if (step1Chip) step1Chip.hidden = !paramsConfirmed;
    if (stepConfirm) stepConfirm.hidden = paramsConfirmed;
    // Going back is only honest while nothing has been shared under these
    // terms; the batch freezes them the moment its first file lands.
    if (stepEdit) stepEdit.hidden = !paramsConfirmed || optionsLocked;
    if (step2Sub) {
      step2Sub.textContent = t(paramsConfirmed ? 'upload.step2_open' : 'upload.step2_locked');
    }
  }

  function setParamsConfirmed(on) {
    paramsConfirmed = on;
    applyOptionState();
    applyStepState();
  }

  if (stepConfirm) {
    stepConfirm.addEventListener('click', () => {
      setParamsConfirmed(true);
      if (stepFiles) stepFiles.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
  }
  if (stepEdit) {
    stepEdit.addEventListener('click', () => {
      if (optionsLocked) return; // the batch already exists; nothing to reopen
      setParamsConfirmed(false);
      if (stepParams) stepParams.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
  }

  function syncCustomExpiry() {
    if (expiresAtWrap && expiresSel) {
      expiresAtWrap.hidden = expiresSel.value !== 'custom';
    }
  }

  // Single-Use is exactly "1 hour" plus "1 download" — it writes those two
  // values rather than carrying a flag of its own, so the request the server
  // receives is indistinguishable from setting them by hand. Turning it off
  // restores what the fields held before, which is why the previous values are
  // captured rather than reset to defaults.
  function setSingleUse(on) {
    if (on === singleUse) return;
    if (on) {
      preSingleUse = {
        expires: expiresSel ? expiresSel.value : '',
        expiresAt: expiresAtInput ? expiresAtInput.value : '',
        max: maxDownloadsInput ? maxDownloadsInput.value : '',
      };
      if (expiresSel) expiresSel.value = '1';
      if (maxDownloadsInput) maxDownloadsInput.value = '1';
    } else if (preSingleUse) {
      if (expiresSel) expiresSel.value = preSingleUse.expires;
      if (expiresAtInput) expiresAtInput.value = preSingleUse.expiresAt;
      if (maxDownloadsInput) maxDownloadsInput.value = preSingleUse.max;
      preSingleUse = null;
    }
    singleUse = on;
    syncCustomExpiry();
    applyOptionState();
  }

  if (singleUseBtn) {
    singleUseBtn.addEventListener('click', () => setSingleUse(!singleUse));
  }

  form.addEventListener('submit', (e) => e.preventDefault());

  // Browsers restore form state on reload/back-forward; always start clean.
  function resetOptions() {
    form.reset();
    if (expiresAtInput) expiresAtInput.value = '';
    singleUse = false;
    preSingleUse = null;
    paramsConfirmed = false;
    syncCustomExpiry();
    applyOptionState();
    applyStepState();
  }
  resetOptions();
  window.addEventListener('pageshow', (e) => {
    if (e.persisted) resetOptions();
  });

  // custom expiry date picker
  if (expiresSel && expiresAtWrap && expiresAtInput) {
    expiresSel.addEventListener('change', () => {
      const custom = expiresSel.value === 'custom';
      syncCustomExpiry();
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
      if (!paramsConfirmed) return; // no drop target until the gate opens
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

  // Uploads run ONE AT A TIME.
  //
  // Firing them in parallel shares the same upstream bandwidth between every
  // request, so the batch finishes no sooner while each individual request
  // takes N times longer to send its body. That is what trips a reverse
  // proxy's per-request read timeout: eight parallel uploads each sat past
  // Traefik's 60s readTimeout and were cut off mid-body, surfacing as 502s,
  // where the same eight sent back-to-back each finish well inside it.
  // Sequential also makes the per-file progress bar and rate mean something.
  let uploadChain = Promise.resolve();
  function enqueue(fn) {
    uploadChain = uploadChain.then(fn).catch(() => {}); // one failure must not stall the queue
    return uploadChain;
  }

  function handleFiles(files) {
    if (!files || files.length === 0) return;
    // A drop lands on the dropzone whether or not its input is disabled, so
    // the gate is enforced here too rather than by the styling alone.
    if (!paramsConfirmed) {
      toast(t('upload.step2_locked'));
      if (stepParams) stepParams.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      return;
    }
    if (sessionSection) sessionSection.hidden = false;
    // One snapshot for the whole drop: a retry must repeat the share settings
    // the user actually chose, not whatever the form holds later on.
    const opts = snapshotOptions();
    for (const file of files) {
      // Rows appear immediately so the queue shows the whole drop, not just
      // the file currently in flight. Each carries its own cancel token from
      // the start, so a file can be cancelled while it is still waiting.
      const row = newQueueRow(file);
      const ctl = { aborted: false, xhr: null };
      const status = row.querySelector('.queue-status');
      const actions = row.querySelector('.queue-actions');
      status.textContent = t('queued');
      actions.appendChild(queueButton('cancel', 'btn-cancel', () => {
        if (ctl.aborted) return;
        ctl.aborted = true;
        if (ctl.xhr) ctl.xhr.abort();
        markRowCancelled(row);
      }));
      enqueue(() => uploadOne(file, opts, row, ctl));
    }
  }

  // Shared by the waiting-row cancel button and uploadOne's own handler.
  function markRowCancelled(row) {
    const status = row.querySelector('.queue-status');
    const actions = row.querySelector('.queue-actions');
    const reason = row.querySelector('.queue-reason');
    row.classList.remove('queue-error', 'queue-done');
    row.classList.add('queue-cancelled');
    status.textContent = t('cancelled');
    row.querySelector('.queue-fill').style.width = '0%';
    reason.textContent = t('reason_cancelled');
    reason.hidden = false;
    actions.textContent = '';
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
    const nameEl = row.querySelector('.queue-name');
    nameEl.textContent = file.name;
    nameEl.title = file.name;
    queue.prepend(row);
    return row;
  }

  async function uploadOne(file, opts, existingRow, existingCtl) {
    // Duck-typed AbortSignal: encryptFile only reads `.aborted`, and XHR has
    // its own abort(), so no AbortController is needed. A queued row hands in
    // the token it was created with, so a cancel pressed while waiting is
    // already recorded by the time this file's turn comes up.
    const ctl = existingCtl || { aborted: false, xhr: null };
    if (ctl.aborted) return;

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

    function showRetry() {
      actions.textContent = '';
      // Retries join the queue rather than running alongside an active upload.
      actions.appendChild(queueButton('retry', 'btn-retry',
        () => enqueue(() => uploadOne(file, opts, row))));
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
      markRowCancelled(row);
      showRetry();
    }));

    // Check the size before encrypting anything. The server refuses an
    // oversize file anyway, but only after the browser has encrypted the whole
    // thing and pushed every byte across — minutes of work and the entire
    // upload's bandwidth spent to be told no. too_large is deliberately not in
    // RETRYABLE: retrying cannot change the outcome.
    if (MAX_UPLOAD > 0 && file.size > MAX_UPLOAD) {
      fail('too_large', t('reason_too_large', fmtSize(file.size), fmtSize(MAX_UPLOAD)));
      return;
    }

    // Expiry, limit and password belong to the batch row, not the member, so
    // the per-file POST carries none of them.
    const fd = new FormData();

    // Encrypt in this tab before anything is sent. The password (when set) is
    // never transmitted: only a token derived from it on a separate KDF
    // branch, which cannot yield the file key.
    const E2E = window.PYXIS_E2E;
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

    let manifestBytes;
    try {
      // Every member gets its own random key, sealed under the batch key. The
      // server stores the sealed blob and can open neither.
      const rawKey = E2E.randomBytes(E2E.KEY_LEN);
      const key = await E2E.importAes(rawKey);
      fd.append('wrapped_key', E2E.b64uEncode(await E2E.wrapFileKey(batch.key, rawKey)));

      // The manifest is built BEFORE encryption and fed to every chunk as
      // additional authenticated data, which is what ties the bytes to their
      // size, count, name, type and batch. The id is generated here rather than
      // taken from the server's row: it has to exist before the upload, and it
      // must be something the server cannot choose.
      // The id is generated here rather than taken from the server's row: it
      // has to exist before the upload, it must be something the server cannot
      // choose, and it is what binds the sealed name to this one file.
      const fileID = E2E.newFileId();
      manifestBytes = E2E.buildManifest({
        id: fileID,
        batch: batch.id,
        size: file.size,
        type: file.type || 'application/octet-stream',
      });

      // The name never goes up in the clear, and never in the manifest — those
      // bytes are stored and served as they are. It travels sealed under its
      // own branch of the batch secret, so a listing can show it without
      // touching the file and the server cannot read it at all.
      fd.append('enc_name', E2E.b64uEncode(
        await E2E.sealName(batch.name, fileID, {
          name: file.name,
          type: file.type || 'application/octet-stream',
        })));

      const cipher = await E2E.encryptFile(file, key, manifestBytes, (f) => {
        fill.style.width = Math.round(f * 100) + '%';
        status.textContent = t('e2e_encrypting');
      }, ctl);
      // The part is named after the id, not the file: a multipart filename is
      // plaintext metadata the server would otherwise see and log.
      fd.append('file', cipher, fileID + '.enc');
      fd.append('e2e', '1');
      fd.append('e2e_version', String(E2E.VERSION));
      fd.append('manifest', E2E.b64uEncode(manifestBytes));
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
        let created = null;
        try { created = JSON.parse(xhr.responseText); } catch (e) { /* handled below */ }
        if (created && created.id) {
          // This browser sealed the name a moment ago, so it is the one place
          // that can still read it without the link.
          rememberName(created.id, file.name);
          recordMember(created.id, file, manifestBytes);
        } else {
          // Without the server's row id the member cannot be entered into the
          // roster, so the link would list a file nothing vouches for. Say so
          // here rather than letting the recipient discover it as a warning.
          reason.textContent = t('reason_roster');
          reason.hidden = false;
        }
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

  const batchState = {
    id: null, fragment: '', key: null, rosterKey: null, name: null,
    count: 0, creating: null,
    // The authenticated member list, rebuilt and re-sealed after every file so
    // the link is verifiable at every moment of an upload session, not only
    // once it ends — people copy the link and send it while files are still
    // going up.
    roster: [], rosterSeq: 0, rosterChain: Promise.resolve(),
  };

  // recordMember adds one uploaded file to the roster and pushes the re-sealed
  // list to the server.
  //
  // Updates are chained rather than fired concurrently: each carries a sequence
  // number and the server keeps only the highest, so two in flight at once
  // would let the smaller list win and silently drop a member from the
  // verified set.
  function recordMember(fileID, file, manifestBytes) {
    const E2E = window.PYXIS_E2E;
    batchState.rosterChain = batchState.rosterChain.then(async () => {
      if (!batchState.id || !batchState.rosterKey) return;
      batchState.roster.push({
        id: fileID,
        name: file.name,
        size: file.size,
        type: file.type || 'application/octet-stream',
        manifest: await E2E.sha256b64u(manifestBytes),
      });
      batchState.rosterSeq++;
      const sealed = await E2E.sealRoster(batchState.rosterKey, batchState.id, {
        v: E2E.VERSION,
        batch: batchState.id,
        seq: batchState.rosterSeq,
        files: batchState.roster,
      });
      const body = new URLSearchParams();
      body.set('roster', E2E.b64uEncode(sealed));
      body.set('seq', String(batchState.rosterSeq));
      await fetch('/batches/' + batchState.id + '/roster', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: body.toString(),
      });
    }).catch((err) => {
      // A roster that failed to store is not a failed upload — the file is
      // safely there and decryptable. It does mean the recipient will be told
      // the member list could not be verified, so it is worth a toast.
      toast(t('reason_roster'));
      // eslint-disable-next-line no-console
      console.warn('roster update failed', err);
    });
    return batchState.rosterChain;
  }

  const batchShare = document.getElementById('batch-share');
  const batchShareUrl = document.getElementById('batch-share-url');
  const batchShareCopy = document.getElementById('batch-share-copy');
  const batchShareQR = document.getElementById('batch-share-qr');
  const batchShareLabel = document.getElementById('batch-share-label');
  const batchShareCount = document.getElementById('batch-share-count');
  const batchShareNote = document.getElementById('batch-share-note');
  const batchShareNew = document.getElementById('batch-share-new');

  function setOptionsLocked(locked) {
    optionsLocked = locked;
    applyOptionState();
    applyStepState();
  }

  // Concurrent uploads all await the same creation: handleFiles starts every
  // file at once, and without this they would each open their own batch.
  async function ensureBatch(opts) {
    if (batchState.id) return batchState;
    if (batchState.creating) return batchState.creating;

    const E2E = window.PYXIS_E2E;
    batchState.creating = (async () => {
      const body = new URLSearchParams();
      if (opts.expiresAt) body.set('expires_at', opts.expiresAt);
      else if (opts.expiresHours !== undefined) body.set('expires_hours', opts.expiresHours);
      body.set('max_downloads', opts.maxDownloads);

      let key;
      let rosterKey;
      let nameKey;
      let fragment = '';
      if (opts.password) {
        const salt = E2E.randomBytes(E2E.SALT_LEN);
        const derived = await E2E.derivePasswordKeys(opts.password, salt, E2E.VERSION);
        key = derived.key;
        rosterKey = derived.roster;
        nameKey = derived.name;
        body.set('auth_salt', E2E.b64uEncode(salt));
        body.set('auth_verifier', E2E.b64uEncode(derived.auth));
      } else {
        // The fragment is the only copy of the batch secret and never leaves
        // this tab — the server sees the batch id and nothing else.
        const secret = E2E.randomBytes(E2E.KEY_LEN);
        fragment = '#' + E2E.b64uEncode(secret);
        const derived = await E2E.deriveBatchKeys(secret, E2E.VERSION);
        key = derived.key;
        rosterKey = derived.roster;
        nameKey = derived.name;
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
      batchState.rosterKey = rosterKey;
      batchState.name = nameKey;
      batchState.roster = [];
      batchState.rosterSeq = 0;
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
      batchState.rosterKey = null;
      batchState.name = null;
      batchState.roster = [];
      batchState.rosterSeq = 0;
      batchState.count = 0;
      batchState.creating = null;
      setOptionsLocked(false);
      // A new link means new terms: step 1 opens again and has to be confirmed
      // before the next file can go anywhere.
      setParamsConfirmed(false);
      batchShare.hidden = true;
      // The queue described the previous link; clearing avoids implying those
      // files are reachable through the next one.
      queue.textContent = '';
      if (sessionSection) sessionSection.hidden = true;
    });
  }
})();
