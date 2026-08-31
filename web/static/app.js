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

    // The name used for the saved file. Starts as the server's copy so the page
    // has something to show, and is replaced by the authenticated one as soon
    // as a decryption succeeds.
    let fileName = e2eRoot.getAttribute('data-name');

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
      if (!m || !m.name || m.name === fileName) return;
      warn(t('e2e_name_changed', fileName, m.name));
      fileName = m.name;
      const heading = document.querySelector('.dl-file-title h1');
      if (heading) heading.textContent = m.name;
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
        E2E.deriveUrlKey(E2E.b64uDecode(secret), e2eVersion)
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
          const { key, auth } = await E2E.derivePasswordKeys(pwInput.value, salt, e2eVersion);
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
      await verifyRoster(data);
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
          .then((k) => { batchKey = k.key; rosterKey = k.roster; return startBatch(); })
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
    if (!confirm(form.getAttribute('data-confirm'))) e.preventDefault();
  });

  // ---- history page: live search ----------------------------------------------

  const search = document.getElementById('file-search');
  const fileList = document.getElementById('file-list');
  // Set by the multi-select block below, which has to react to rows being
  // filtered away; declared here because the search handler runs first.
  let onListFiltered = () => {};
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

    const boxes = () =>
      Array.from(fileList.querySelectorAll('.file-select input[type="checkbox"]'));
    // Only rows the search leaves visible take part: "select all" has to mean
    // what the list is showing, not what it would show unfiltered.
    const visibleBoxes = () => boxes().filter((b) => !b.closest('.file-item').hidden);

    if (boxes().length === 0) bulkForm.hidden = true;

    function sync() {
      const all = visibleBoxes();
      const picked = all.filter((b) => b.checked);
      bulkBtn.disabled = picked.length === 0;
      bulkCount.textContent = picked.length === 0 ? emptyLabel : t('selected', picked.length);
      bulkForm.setAttribute('data-confirm', t('confirm_delete_many', picked.length));
      bulkAll.checked = all.length > 0 && picked.length === all.length;
      bulkAll.indeterminate = picked.length > 0 && picked.length < all.length;
    }

    bulkAll.addEventListener('change', () => {
      for (const b of visibleBoxes()) b.checked = bulkAll.checked;
      anchor = null;
      sync();
    });

    fileList.addEventListener('click', (e) => {
      const box = e.target.closest && e.target.closest('.file-select input[type="checkbox"]');
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
    fileList.addEventListener('change', sync);

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

  // Two independent reasons the share options can be read-only: the batch link
  // has been created and its terms are frozen, or Single-Use is driving them.
  // Both are folded into applyOptionState so neither can re-enable a field the
  // other still wants disabled — declared before resetOptions() runs, which
  // calls it.
  let optionsLocked = false;
  let singleUse = false;
  let preSingleUse = null;

  function applyOptionState() {
    for (const el of [expiresSel, expiresAtInput, passwordInput, maxDownloadsInput]) {
      if (el) el.disabled = optionsLocked;
    }
    // Single-Use owns expiry and the download limit; the password stays free.
    if (!optionsLocked && singleUse) {
      for (const el of [expiresSel, expiresAtInput, maxDownloadsInput]) {
        if (el) el.disabled = true;
      }
    }
    if (optionsBox) optionsBox.classList.toggle('options-locked', optionsLocked);
    if (singleUseBtn) {
      singleUseBtn.disabled = optionsLocked;
      singleUseBtn.setAttribute('aria-pressed', singleUse ? 'true' : 'false');
    }
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
    syncCustomExpiry();
    applyOptionState();
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
      manifestBytes = E2E.buildManifest({
        id: E2E.newFileId(),
        batch: batch.id,
        size: file.size,
        name: file.name,
        type: file.type || 'application/octet-stream',
      });

      const cipher = await E2E.encryptFile(file, key, manifestBytes, (f) => {
        fill.style.width = Math.round(f * 100) + '%';
        status.textContent = t('e2e_encrypting');
      }, ctl);
      fd.append('file', cipher, file.name);
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
    id: null, fragment: '', key: null, rosterKey: null,
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
      let fragment = '';
      if (opts.password) {
        const salt = E2E.randomBytes(E2E.SALT_LEN);
        const derived = await E2E.derivePasswordKeys(opts.password, salt, E2E.VERSION);
        key = derived.key;
        rosterKey = derived.roster;
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
      batchState.roster = [];
      batchState.rosterSeq = 0;
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
