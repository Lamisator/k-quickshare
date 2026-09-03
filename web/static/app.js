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

  // From container version 5 the server is told nothing about a file's type, so
  // it can no longer pick the icon or decide whether a preview is on offer.
  // Both moves here, where the type is known — it comes out of the sealed name
  // blob, which costs one short decryption and no ciphertext at all. These two
  // mirror iconKind() and previewKind() in handlers.go, which still run for
  // shares written before version 5.
  function iconKindFor(contentType, name) {
    const ct = String(contentType || '').toLowerCase().split(';')[0].trim();
    const dot = String(name || '').lastIndexOf('.');
    const ext = dot > 0 ? String(name).slice(dot + 1).toLowerCase() : '';
    if (ct.startsWith('image/')) return 'image';
    if (ct.startsWith('video/')) return 'video';
    if (ct.startsWith('audio/')) return 'audio';
    if (ct === 'application/pdf' || ext === 'pdf') return 'pdf';
    if (ct.startsWith('text/') || ct === 'application/json' || ct === 'application/xml') return 'text';
    if (['zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'zst', '7z', 'rar'].indexOf(ext) >= 0) return 'archive';
    if (['doc', 'docx', 'odt', 'xls', 'xlsx', 'ods', 'ppt', 'pptx', 'odp'].indexOf(ext) >= 0) return 'doc';
    return 'generic';
  }

  function previewKindFor(contentType, size) {
    const ct = String(contentType || '').toLowerCase().split(';')[0].trim();
    if (ct.startsWith('image/')) return 'image';
    if (ct.startsWith('video/')) return 'video';
    if (ct.startsWith('audio/')) return 'audio';
    if (ct === 'application/pdf') return 'pdf';
    if (ct.startsWith('text/') || ct === 'application/json' || ct === 'application/xml') {
      return Number(size) <= 2 * 1024 * 1024 ? 'text' : '';
    }
    return '';
  }

  function fileIcon(kind) {
    const k = ICON_KINDS.indexOf(kind) >= 0 ? kind : 'generic';
    const span = document.createElement('span');
    span.className = 'ficon ficon-' + k;
    span.setAttribute('aria-hidden', 'true');
    span.innerHTML = '<svg class="ficon-svg" viewBox="0 0 24 24" width="20" height="20">' +
      '<use href="#fi-' + k + '"/></svg>';
    return span;
  }

  // ---- what is really inside a video --------------------------------------
  //
  // A .mov off a phone and an .mp4 off a camera are the same ISO base media
  // container wearing different brands, and neither MIME type says a word
  // about the codec inside — which is the thing that actually decides whether
  // a browser can play the file. An iPhone .mov is usually HEVC, and a browser
  // with no HEVC decoder fails on it in one of two ways:
  //
  //   * it refuses the file, which the recipient reads as "MIME type not
  //     supported" and nothing else;
  //   * or it opens the file, drops the video track it cannot decode, and
  //     plays the SOUND. Measured on Chromium 152 with an HEVC .mov:
  //     loadedmetadata, canplay, playing and timeupdate all fire, no error
  //     event ever does, and videoWidth stays 0. A black rectangle with audio
  //     coming out of it, and not one signal that anything went wrong.
  //
  // canPlayType() cannot settle it in advance either: the codec string it
  // wants carries a profile and a level, a sample entry only gives the four
  // characters in front of them, and a wrong "no" would withhold a preview
  // that would have played. So the browser is left to try, and the container
  // is walked far enough to name the codec — which is what turns the silent
  // second case into something that can be explained, and what tells it apart
  // from an audio-only file behaving perfectly.
  //
  // The walk reads the decrypted plaintext and nothing else: no manifest, no
  // ciphertext, and nothing is re-serialised.

  // The boxes on the way down to the sample table. Everything else is skipped
  // by its own length, mdat included, so a 4 GB recording costs no reads.
  const ISO_PARENTS = ['moov', 'trak', 'mdia', 'minf', 'stbl'];

  // Sample formats worth naming to somebody whose browser just refused one.
  const VIDEO_CODECS = {
    avc1: 'H.264', avc3: 'H.264',
    hvc1: 'HEVC (H.265)', hev1: 'HEVC (H.265)',
    dvh1: 'Dolby Vision (HEVC)', dvhe: 'Dolby Vision (HEVC)',
    av01: 'AV1', vp08: 'VP8', vp09: 'VP9',
    mp4v: 'MPEG-4 Visual', jpeg: 'Motion JPEG', mjpa: 'Motion JPEG',
    ap4h: 'Apple ProRes', ap4x: 'Apple ProRes', apch: 'Apple ProRes',
    apcn: 'Apple ProRes', apco: 'Apple ProRes', apcs: 'Apple ProRes',
  };

  const be32 = (b, at) => ((b[at] << 24 | b[at + 1] << 16 | b[at + 2] << 8 | b[at + 3]) >>> 0);
  const fourcc = (b, at) => String.fromCharCode(b[at], b[at + 1], b[at + 2], b[at + 3]);

  // isoWalk collects the sample entry formats between start and end. Depth and
  // box count are capped: this runs over a file a stranger uploaded, and a
  // malformed one must not be able to spin the tab.
  async function isoWalk(blob, start, end, depth, out, budget) {
    let at = start;
    while (at + 8 <= end && budget.n > 0) {
      budget.n--;
      const head = new Uint8Array(await blob.slice(at, Math.min(at + 16, end)).arrayBuffer());
      if (head.length < 8) return;
      let size = be32(head, 0);
      const type = fourcc(head, 4);
      let body = at + 8;
      if (size === 1) {
        // A 64-bit length belongs to the mdat of a long recording. The high
        // word is past anything a browser holds in a blob, so a file claiming
        // one is not walked further rather than being read with a wrapped
        // offset.
        if (head.length < 16 || be32(head, 8) !== 0) return;
        size = be32(head, 12);
        body = at + 16;
      } else if (size === 0) {
        size = end - at; // a zero length means "to the end of the file"
      }
      if (size < body - at) return; // nonsense length: stop rather than loop
      const stop = Math.min(at + size, end);
      if (type === 'stsd') {
        // A FullBox: four bytes of version and flags, four of entry count,
        // then the entries themselves.
        await isoSampleEntries(blob, body + 8, stop, out, budget);
      } else if (depth < 6 && ISO_PARENTS.indexOf(type) >= 0) {
        await isoWalk(blob, body, stop, depth + 1, out, budget);
      }
      at += size;
    }
  }

  async function isoSampleEntries(blob, at, end, out, budget) {
    while (at + 8 <= end && budget.n > 0) {
      budget.n--;
      const head = new Uint8Array(await blob.slice(at, at + 8).arrayBuffer());
      if (head.length < 8) return;
      const size = be32(head, 0);
      out.push(fourcc(head, 4));
      if (size < 8) return;
      at += size;
    }
  }

  // sniffIso describes an ISO base media file — .mp4, .m4a, .m4v, .mov and the
  // rest of the family — or returns null for anything that is not one, such as
  // a .webm, an .avi, or a file that is not what its type claims.
  async function sniffIso(blob) {
    const head = new Uint8Array(await blob.slice(0, 8).arrayBuffer());
    if (head.length < 8) return null;
    // Every such file opens with a box header, in practice one of these: ftyp
    // since MP4, and the older QuickTime layouts that start straight in on the
    // movie or the media data.
    if (['ftyp', 'moov', 'mdat', 'wide', 'skip', 'free', 'pnot'].indexOf(fourcc(head, 4)) < 0) {
      return null;
    }
    const formats = [];
    await isoWalk(blob, 0, blob.size, 0, formats, { n: 4000 });
    if (formats.length === 0) return null;
    const video = formats.filter((f) => VIDEO_CODECS[f])[0] || '';
    return { formats: formats, video: video, label: VIDEO_CODECS[video] || '' };
  }

  // watchPlayable replaces a player with a plain explanation if the browser
  // turns out not to be able to play what it was handed.
  //
  // Three failures, and they look nothing alike:
  //
  //   * a flat refusal — the error event, which is what a browser does with a
  //     container or a codec it will not open at all;
  //   * sound but no picture — the file opened, the audio track plays and no
  //     video track ever arrives. Nothing errors, so it is read off
  //     videoWidth, and only for a file the walk above says HAS a video track:
  //     an audio-only .m4a reports the same zero and is perfectly healthy;
  //   * a video track that is announced and then decodes nothing, which shows
  //     up as playback running with the decoded frame count stuck at zero.
  function watchPlayable(box, el, kind, iso) {
    let settled = false;
    const fail = () => {
      if (settled) return;
      settled = true;
      // Tear the player down properly: revoking alone leaves audio playing.
      el.pause();
      URL.revokeObjectURL(el.src);
      el.removeAttribute('src');
      el.load();
      el.remove();
      const p = document.createElement('p');
      p.className = 'dl-nopreview';
      p.textContent = iso && iso.label ? t('preview_codec', iso.label) : t('preview_unplayable');
      box.appendChild(p);
    };
    el.addEventListener('error', fail);
    if (kind !== 'video' || !iso || !iso.video) return;

    // HAVE_METADATA is where a working file already knows its dimensions.
    const checkPicture = () => {
      if (el.readyState >= 1 && el.videoWidth === 0) fail();
    };
    el.addEventListener('loadedmetadata', checkPicture);
    el.addEventListener('loadeddata', checkPicture);
    // The dimensions can be right and the decoder still produce nothing, and
    // that only becomes visible once playback has actually run for a moment.
    el.addEventListener('timeupdate', () => {
      if (settled || el.currentTime < 0.4 || !el.getVideoPlaybackQuality) return;
      if (el.getVideoPlaybackQuality().totalVideoFrames === 0) fail();
    });
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
    } else if (kind === 'image') {
      const el = document.createElement('img');
      el.src = URL.createObjectURL(blob);
      el.alt = name;
      makeZoomable(el, name);
      box.appendChild(el);
    } else {
      const el = document.createElement(kind === 'video' ? 'video' : 'audio');
      el.controls = true;
      el.preload = 'metadata';
      const iso = await sniffIso(blob);
      // Same bytes, honest label: a .mov is an ISO base media file like any
      // .mp4, and the family is what a demuxer needs to be told. Chromium
      // disclaims video/quicktime when asked (canPlayType returns "") even
      // though it does in fact open one, and a player that takes that type at
      // its word has no reason to try. The sender's own type is left alone
      // everywhere else, the download included.
      el.src = URL.createObjectURL(iso ? blob.slice(0, blob.size, kind + '/mp4') : blob);
      watchPlayable(box, el, kind, iso);
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

  // ---- click-to-enlarge, then zoom ----------------------------------------
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
  //
  // Once it is open the picture can be zoomed into: the wheel, a trackpad
  // pinch (which browsers deliver as ctrl+wheel), two fingers on a touchscreen
  // and the +/-/0 keys all end up in ONE place — a scale and a translation in
  // screen pixels — that applyZoom() writes out as a CSS transform.
  //
  // Nothing here scrolls. Panning is part of the same transform, deliberately:
  // a scroll container would hand the gesture back to the browser at every
  // edge, and on a phone that means the page behind the overlay starts moving
  // in the middle of a pinch.
  const ZOOM_MIN = 1;   // 1 is the whole picture, fitted to the viewport
  const ZOOM_MAX = 12;
  const ZOOM_STEP = 1.3; // one press of + or -
  const ZOOM_PAN_KEY = 60; // pixels one arrow key pans a zoomed-in picture

  let zoomOverlay = null;
  const zoomState = { scale: 1, tx: 0, ty: 0 };
  // Pointers currently down on the overlay, by pointerId. Two of them are a
  // pinch, one is a pan.
  const zoomPointers = new Map();
  let zoomPinch = null;   // spread and midpoint of the previous pinch frame
  let zoomDragged = 0;    // pixels travelled, so a pan does not read as a click

  // The picture is letterboxed inside the overlay by object-fit: contain, so
  // the box it really occupies is smaller than the element in one dimension.
  // Panning is clamped against THAT box — clamping against the element would
  // let a portrait photo be dragged sideways into empty space.
  function zoomFitted() {
    const el = zoomOverlay.img;
    const nw = el.naturalWidth, nh = el.naturalHeight;
    if (!nw || !nh) return { w: el.clientWidth, h: el.clientHeight };
    const s = Math.min(el.clientWidth / nw, el.clientHeight / nh);
    return { w: nw * s, h: nh * s };
  }

  function applyZoom() {
    const el = zoomOverlay.img;
    const fit = zoomFitted();
    const s = zoomState.scale;
    // Half the overhang is as far as an edge can travel: past that there is
    // nothing left to pan towards, and an axis with no overhang at all snaps
    // back to centred.
    const maxX = Math.max(0, (fit.w * s - el.clientWidth) / 2);
    const maxY = Math.max(0, (fit.h * s - el.clientHeight) / 2);
    zoomState.tx = Math.max(-maxX, Math.min(maxX, zoomState.tx));
    zoomState.ty = Math.max(-maxY, Math.min(maxY, zoomState.ty));
    el.style.transform =
      'translate(' + zoomState.tx + 'px, ' + zoomState.ty + 'px) scale(' + s + ')';

    const zoomed = s > ZOOM_MIN + 0.001;
    zoomOverlay.el.classList.toggle('zoomed', zoomed);
    el.title = zoomed ? t('zoom_out') : t('zoom_hint');
    zoomOverlay.hint.textContent = zoomed ? Math.round(s * 100) + '%' : t('zoom_hint');
  }

  // zoomTo scales to `next` while holding the point of the picture that sits
  // under (cx, cy) — a viewport coordinate: the cursor, or the midpoint
  // between two fingers — exactly where it is.
  //
  // The transform's origin is the element's centre c, so a point p offsets
  // from it lands at c + t + s·p. Solving for the t that keeps the anchor
  // still across a scale change gives t' = d − (s'/s)·(d − t), with d the
  // anchor's offset from c.
  function zoomTo(next, cx, cy) {
    const box = zoomOverlay.el.getBoundingClientRect();
    const s = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, next));
    const k = s / zoomState.scale;
    const dx = cx - (box.left + box.width / 2);
    const dy = cy - (box.top + box.height / 2);
    zoomState.tx = dx - k * (dx - zoomState.tx);
    zoomState.ty = dy - k * (dy - zoomState.ty);
    zoomState.scale = s;
    applyZoom();
  }

  // Zooms about the middle of the viewport, for the keys and for anything else
  // with no pointer behind it.
  function zoomByStep(factor) {
    const box = zoomOverlay.el.getBoundingClientRect();
    zoomTo(zoomState.scale * factor, box.left + box.width / 2, box.top + box.height / 2);
  }

  function resetZoom() {
    zoomState.scale = 1;
    zoomState.tx = 0;
    zoomState.ty = 0;
    applyZoom();
  }

  // Spread and midpoint of the two live pointers, the raw material of a pinch.
  function pinchFrame() {
    const [a, b] = Array.from(zoomPointers.values());
    return {
      dist: Math.hypot(a.x - b.x, a.y - b.y),
      x: (a.x + b.x) / 2,
      y: (a.y + b.y) / 2,
    };
  }

  function buildZoomOverlay() {
    const el = document.createElement('dialog');
    el.className = 'zoom';

    const img = document.createElement('img');
    img.className = 'zoom-img';
    // Without this a drag on a picture becomes the browser's own image drag
    // halfway through, and the pan stops dead.
    img.draggable = false;

    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'zoom-close';
    close.innerHTML =
      '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
    // Stops the click below from reading the button as a click on the picture.
    close.addEventListener('click', (e) => { e.stopPropagation(); el.close(); });

    // Says what the gestures are while the picture is fitted, and reads out the
    // zoom level once it is not.
    const hint = document.createElement('span');
    hint.className = 'zoom-hint';

    zoomOverlay = { el: el, img: img, close: close, hint: hint };

    // The wheel sits on the dialog, not the picture, so the letterboxed strips
    // beside a photo zoom too rather than feeling dead.
    el.addEventListener('wheel', (e) => {
      e.preventDefault();
      // deltaY is in lines or pages in some browsers; normalising to pixels
      // keeps one notch of the wheel worth the same everywhere.
      const px = e.deltaY * (e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? el.clientHeight : 1);
      // A trackpad pinch arrives as ctrl+wheel with far smaller deltas than a
      // real wheel, so it needs the coarser rate to travel the same distance.
      zoomTo(zoomState.scale * Math.exp(-px * (e.ctrlKey ? 0.01 : 0.0025)), e.clientX, e.clientY);
    }, { passive: false });

    el.addEventListener('pointerdown', (e) => {
      if (close.contains(e.target)) return;
      if (e.pointerType === 'mouse' && e.button !== 0) return;
      zoomPointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      zoomDragged = 0;
      zoomPinch = zoomPointers.size === 2 ? pinchFrame() : null;
      el.setPointerCapture(e.pointerId);
      if (zoomState.scale > ZOOM_MIN) el.classList.add('panning');
    });

    el.addEventListener('pointermove', (e) => {
      const p = zoomPointers.get(e.pointerId);
      if (!p) return;
      const dx = e.clientX - p.x, dy = e.clientY - p.y;
      p.x = e.clientX;
      p.y = e.clientY;
      zoomDragged += Math.hypot(dx, dy);

      if (zoomPointers.size >= 2) {
        const now = pinchFrame();
        if (zoomPinch && zoomPinch.dist > 0) {
          // Two fingers do both jobs at once: the spread scales, and the
          // midpoint's own travel drags the picture along with the hand.
          zoomState.tx += now.x - zoomPinch.x;
          zoomState.ty += now.y - zoomPinch.y;
          zoomTo(zoomState.scale * (now.dist / zoomPinch.dist), now.x, now.y);
        }
        zoomPinch = now;
      } else if (zoomState.scale > ZOOM_MIN) {
        zoomState.tx += dx;
        zoomState.ty += dy;
        applyZoom();
      }
    });

    const endPointer = (e) => {
      if (!zoomPointers.delete(e.pointerId)) return;
      // Lifting one finger of a pinch leaves the other one panning, and the
      // stale frame would make the picture jump on the next move.
      zoomPinch = zoomPointers.size === 2 ? pinchFrame() : null;
      if (zoomPointers.size === 0) el.classList.remove('panning');
    };
    el.addEventListener('pointerup', endPointer);
    el.addEventListener('pointercancel', endPointer);

    // One rule for the picture and the backdrop alike: a zoomed-in picture
    // goes back to fitting the screen, a fitted one goes away. A pan that
    // ended where it started is still a click, hence the travel check.
    // detail > 0 keeps a keyboard-activated button, which reports a click at
    // (0, 0), from reading as a click on the overlay.
    el.addEventListener('click', (e) => {
      if (e.detail === 0 || zoomDragged > 4) return;
      if (zoomState.scale > ZOOM_MIN) resetZoom();
      else el.close();
    });

    el.addEventListener('keydown', (e) => {
      if (e.key === '+' || e.key === '=') { e.preventDefault(); zoomByStep(ZOOM_STEP); }
      else if (e.key === '-' || e.key === '_') { e.preventDefault(); zoomByStep(1 / ZOOM_STEP); }
      else if (e.key === '0') { e.preventDefault(); resetZoom(); }
      else if (zoomState.scale > ZOOM_MIN &&
               ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].indexOf(e.key) >= 0) {
        // Only while zoomed in: fitted, these keys belong to the gallery
        // underneath, which steps through the files with them.
        e.preventDefault();
        zoomState.tx += (e.key === 'ArrowLeft' ? 1 : e.key === 'ArrowRight' ? -1 : 0) * ZOOM_PAN_KEY;
        zoomState.ty += (e.key === 'ArrowUp' ? 1 : e.key === 'ArrowDown' ? -1 : 0) * ZOOM_PAN_KEY;
        applyZoom();
      }
    });

    // naturalWidth is 0 until the blob has decoded, and the clamp above needs
    // it; a fresh picture therefore gets a second pass once it is there.
    img.addEventListener('load', applyZoom);
    // Rotating a phone changes what counts as fitted, and can leave a picture
    // panned past its new edge.
    window.addEventListener('resize', () => { if (el.open) applyZoom(); });

    el.appendChild(img);
    el.appendChild(close);
    el.appendChild(hint);
    document.body.appendChild(el);
  }

  function openZoom(src, name) {
    if (!zoomOverlay) buildZoomOverlay();
    zoomOverlay.img.src = src;
    zoomOverlay.img.alt = name || '';
    zoomOverlay.el.setAttribute('aria-label', name || t('zoom_in'));
    zoomOverlay.close.setAttribute('aria-label', t('gallery_close'));
    // A previous viewing may have been left zoomed into a corner.
    zoomPointers.clear();
    zoomPinch = null;
    zoomDragged = 0;
    resetZoom();
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

  // ---- storage bars --------------------------------------------------------
  //
  // Width is applied here rather than as an inline style attribute, which the
  // Content-Security-Policy (style-src 'self') deliberately forbids.
  function applyBarWidths(root) {
    root.querySelectorAll('.disk-fill[data-pct]').forEach((el) => {
      const pct = parseFloat(el.getAttribute('data-pct'));
      if (!isNaN(pct)) el.style.width = Math.max(0, Math.min(100, pct)) + '%';
    });
  }
  applyBarWidths(document);

  // An upload changes what both bars say, so they are refetched when one
  // lands. /usage answers with the very markup the shell rendered, so this
  // does not reimplement the quota arithmetic or the warning thresholds —
  // there is nothing here that could disagree with a reload.
  //
  // Requests are coalesced rather than fired per file: a drop of forty files
  // finishes forty times, and the bar only has to be right after the last one.
  // A refresh asked for while one is in flight is remembered and run once it
  // returns, so the final state is never the one we skipped.
  const storageBars = document.getElementById('storage-bars');
  let barsTimer = null;
  let barsInFlight = false;
  let barsAgain = false;

  // swapBars carries the old positions across the replacement so each bar
  // animates from where it was to where it now is. Without this the fills are
  // rebuilt already at their new width and nothing appears to happen, which is
  // the opposite of the point. Matched on the section's aria-label, so a bar
  // that was not there a moment ago starts from empty, as it should.
  function swapBars(html) {
    const before = new Map();
    storageBars.querySelectorAll('.disk-bar').forEach((sec) => {
      const fill = sec.querySelector('.disk-fill');
      if (fill) before.set(sec.getAttribute('aria-label'), fill.style.width);
    });
    storageBars.innerHTML = html;
    storageBars.querySelectorAll('.disk-bar').forEach((sec) => {
      const fill = sec.querySelector('.disk-fill');
      const was = before.get(sec.getAttribute('aria-label'));
      if (fill && was) fill.style.width = was;
    });
    void storageBars.offsetWidth; // settle the old widths before setting the new
    applyBarWidths(storageBars);
  }

  async function fetchStorageBars() {
    if (barsInFlight) { barsAgain = true; return; }
    barsInFlight = true;
    try {
      const res = await fetch('/usage', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        // The figures are per-user and change on every upload.
        cache: 'no-store',
      });
      // A 401 here means the session went while files were going up. The
      // upload itself reports that; silently swapping the bars for whatever
      // the login page returned would be worse than leaving them stale.
      if (res.ok) swapBars(await res.text());
    } catch (err) {
      // Offline, or the request was cut off. The bars keep their last known
      // figures; the next upload asks again.
    } finally {
      barsInFlight = false;
      if (barsAgain) { barsAgain = false; fetchStorageBars(); }
    }
  }

  function refreshStorageBars() {
    if (!storageBars) return;
    clearTimeout(barsTimer);
    barsTimer = setTimeout(fetchStorageBars, 400);
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

  // ---- end-to-end encrypted landing page ---------------------------------------
  // The ciphertext is fetched as-is and decrypted here; the plaintext never
  // exists outside this tab.

  const e2eRoot = document.getElementById('dl-root');
  if (e2eRoot && e2eRoot.getAttribute('data-e2e') === '1') {
    const E2E = window.PYXIS_E2E;
    const fileId = e2eRoot.getAttribute('data-file');
    const mode = e2eRoot.getAttribute('data-mode');
    let fileType = e2eRoot.getAttribute('data-type');
    const fileSize = Number(e2eRoot.getAttribute('data-size')) || 0;
    // Empty from container version 5 on: the server no longer knows the type,
    // so it cannot decide whether a preview is on offer. The sealed name blob
    // settles both, before any ciphertext is fetched.
    let previewKind = e2eRoot.getAttribute('data-preview-kind');
    const previewsAllowed = e2eRoot.getAttribute('data-limited') !== '1';
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
        if (opened.type) {
          fileType = opened.type;
          const icon = document.querySelector('.dl-file-head .ficon');
          if (icon) icon.replaceWith(fileIcon(iconKindFor(fileType, opened.name)));
          const meta = document.querySelector('.dl-file-title .muted');
          if (meta) meta.textContent = fmtSize(fileSize) + ' · ' + fileType;
          // The server sent no preview kind for a version 5 share; now that the
          // type is known, this page can make that decision itself.
          if (!previewKind && previewsAllowed) {
            previewKind = previewKindFor(fileType, fileSize);
          }
        }
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

    // The same controller serves two pages. A BATCH is one link, one secret,
    // one member list. An INBOX is a drop: several deliveries from people who
    // never met, each with its own KEM encapsulation, its own key schedule and
    // its own sealed roster.
    //
    // The difference is confined to two things — where the keys come from, and
    // which URL serves the bytes. Everything after that is identical, so the
    // member list stays FLAT and each member simply carries its own key set and
    // remembers which delivery it belongs to. Grouping is then presentation,
    // and the roster check, the download accounting, the preview, the gallery
    // and the zip writer stay in one place instead of two.
    const isInbox = batchRoot.getAttribute('data-source') === 'inbox';
    const dropId = batchRoot.getAttribute('data-drop');
    const rawBase = isInbox ? '/i/' + dropId : '/b/' + batchId;
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
    // Set on an inbox only: the X-Wing decapsulation key, derived from the
    // private link's fragment. It never leaves this tab and is the one thing
    // that can turn a delivery's encapsulation into a key schedule.
    let kemSeed = null;

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
      if (isInbox) return loadInbox();
      const res = await fetch('/b/' + batchId + '/manifest', {
        headers: { Accept: 'application/json' },
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      members = data.files || [];
      // One link, one secret: every member opens under the same keys.
      for (const m of members) m.keys = { key: batchKey, roster: rosterKey, name: nameKey };
      batchVersion = Number(data.e2eVersion) || 1;
      await openNames();
      await verifyRoster(data, members);
    }

    // loadInbox turns a drop's deliveries into the flat member list the rest of
    // this controller already knows how to render.
    //
    // One decapsulation per delivery, and it is the only asymmetric operation
    // on the page: everything under it — unwrapping a file key, opening a
    // sealed name, checking a roster — is the same symmetric machinery a batch
    // link uses, because the shared secret has the same shape as the secret a
    // batch link carries.
    async function loadInbox() {
      const res = await fetch('/i/' + dropId + '/manifest', { headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      const subs = data.submissions || [];
      const dropVersion = Number(batchRoot.getAttribute('data-version')) || 1;
      members = [];
      const notes = [];
      for (let i = 0; i < subs.length; i++) {
        const sub = subs[i];
        const group = {
          id: sub.id,
          index: i + 1,
          receivedAt: sub.receivedAt,
          from: '',
          message: '',
        };
        let keys;
        try {
          const ss = E2E.dropDecapsulate(kemSeed, E2E.b64uDecode(sub.kemCt));
          keys = await E2E.deriveSubmissionKeys(ss, E2E.b64uDecode(sub.kemCt), dropVersion);
        } catch (err) {
          // A delivery this key cannot open is reported, not hidden: it is
          // either damage or something the server put here that no holder of
          // the public link ever sealed.
          group.failed = true;
          notes.push(t('inbox_note_sealed'));
          continue;
        }
        if (sub.encNote) {
          try {
            const opened = await E2E.openNote(keys.note, sub.id, E2E.b64uDecode(sub.encNote));
            group.from = opened.from || '';
            group.message = opened.message || '';
          } catch (err) {
            notes.push(t('inbox_note_sealed'));
          }
        }
        const subMembers = sub.files || [];
        for (const m of subMembers) {
          m.keys = keys;
          m.group = group;
        }
        batchVersion = Number(sub.e2eVersion) || batchVersion;
        // Each delivery vouches for its own membership, so the roster is
        // checked per delivery and against that delivery's members only.
        await openNames(subMembers);
        await verifyRoster(sub, subMembers, sub.id);
        // Appended AFTER the check, because verifyRoster may put a delivery
        // back into the order its sender sealed.
        for (const m of subMembers) members.push(m);
      }
      if (notes.length) warn(Array.from(new Set(notes)));
    }

    // From container version 4 the listing carries no names, only a sealed blob
    // per member. Opening them costs one AES-GCM decryption each — no
    // ciphertext is fetched and no download slot is spent — which is exactly
    // why the name is sealed apart from the file it belongs to.
    async function openNames(list) {
      for (const m of (list || members)) {
        if (m.name || !m.encName || !m.keys || !m.keys.name) continue;
        try {
          const opened = await E2E.openName(m.keys.name, m.manifestId, E2E.b64uDecode(m.encName));
          m.name = opened.name;
          // The type it was sealed with is authenticated, and from container
          // version 5 it is the ONLY copy: the server has none. The icon and
          // the preview decision follow from it here rather than arriving with
          // the listing.
          if (opened.type) m.contentType = opened.type;
          m.iconKind = iconKindFor(m.contentType, m.name);
          // A limited batch offers no previews at all — pulling one spends a
          // download slot — and the server says so by sending previewKind
          // empty for every member. Only widen that when it is allowed to.
          if (m.previewsAllowed) m.previewKind = previewKindFor(m.contentType, m.size);
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
    //
    // On an inbox this runs once per delivery, over that delivery's members and
    // under that delivery's own roster key: a drop's deliveries vouch for
    // themselves and for nothing else. One sender cannot sign for another's
    // files, which is exactly the guarantee a drop can and cannot give.
    async function verifyRoster(data, list, scopeId) {
      const notes = [];
      const scope = scopeId || batchId;
      const group = list || members;
      const rKey = group.length && group[0].keys ? group[0].keys.roster : rosterKey;
      if (batchVersion < 2) {
        // A pre-version-2 batch never had a roster. Say so once rather than
        // implying a guarantee this link cannot give.
        warn([t('batch_legacy')]);
        return;
      }
      let roster;
      try {
        if (!data.roster) throw new Error('no roster');
        roster = await E2E.openRoster(rKey, scope, E2E.b64uDecode(data.roster));
      } catch (err) {
        // Either the server has no roster for a batch that must have one, or it
        // does not open under this link's key. Both mean the member list is
        // unverifiable, which is the strongest statement this page can make.
        for (const m of group) m.unverified = true;
        warn([t('batch_no_roster')]);
        return;
      }

      const byID = new Map();
      for (const f of roster.files || []) byID.set(f.id, f);

      for (const m of group) {
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
          if (E2E.parseManifest(E2E.b64uDecode(m.manifest)).batch !== scope) {
            m.unverified = true;
          }
        } catch (err) {
          m.unverified = true;
        }
      }

      const extra = group.filter((m) => m.unverified).length;
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
        const servedOrder = group.map((m) => m.id).join(' ');
        const sealedOrder = (roster.files || []).map((f) => f.id).join(' ');
        if (servedOrder !== sealedOrder) {
          notes.push(t('batch_reordered'));
          // Restore the sealed order rather than only complaining about it.
          const pos = new Map((roster.files || []).map((f, i) => [f.id, i]));
          group.sort((a, b) => pos.get(a.id) - pos.get(b.id));
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
        const fileKey = await E2E.unwrapFileKey(m.keys.key, E2E.b64uDecode(m.wrappedKey));
        const buf = await fetchWithProgress(rawBase + '/f/' + m.id + '/raw',
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

    // A delivery header carries what the sender chose to say, and says plainly
    // that nothing verifies it. Anyone with the public link can write anything
    // here — that is what a public drop box is — so the page must not present a
    // typed name the way it presents a decrypted file name.
    function deliveryHeader(group, numbered) {
      const li = document.createElement('li');
      li.className = 'batch-group';
      const title = document.createElement('span');
      title.className = 'batch-group-title';
      // Numbering a delivery only makes sense beside others.
      title.textContent = numbered ? t('inbox_delivery', String(group.index))
        : (group.from ? '' : t('inbox_anonymous'));
      if (group.from) {
        const from = document.createElement('span');
        from.className = 'batch-group-from';
        from.textContent = numbered ? t('inbox_from', group.from) : group.from;
        // Said out loud rather than implied: this is a name someone typed into
        // a public form, and the page must not dress it up as an identity.
        from.title = t('inbox_unverified_sender');
        if (title.textContent) title.appendChild(document.createTextNode(' '));
        title.appendChild(from);
      }
      li.appendChild(title);

      const meta = document.createElement('span');
      meta.className = 'batch-group-meta muted';
      const when = group.receivedAt ? new Date(group.receivedAt) : null;
      meta.textContent = [
        when && !isNaN(when) ? when.toLocaleString() : '',
        group.from ? '' : t('inbox_anonymous'),
      ].filter(Boolean).join(' · ');
      li.appendChild(meta);

      if (group.message) {
        const msg = document.createElement('p');
        msg.className = 'batch-group-message';
        msg.textContent = group.message;
        li.appendChild(msg);
      }
      return li;
    }

    function renderList() {
      listEl.textContent = '';
      rowUI.clear();
      let total = 0;
      for (const m of members) total += Number(m.size) || 0;
      summaryEl.textContent = fileCountLabel(members.length) + ' · ' + fmtSize(total);
      if (isInbox && members.length === 0) summaryEl.textContent = t('inbox_empty');
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
      let lastGroup = null;
      for (const m of members) {
        // One header per delivery, drawn when there is something to say: more
        // than one delivery to separate, or a sender who wrote a name or a
        // message. A lone anonymous delivery gets none, so a drop that received
        // one thing reads exactly like a batch — but a note must never be
        // swallowed by that simplification, because it is the only thing the
        // sender got to tell the recipient.
        const several = members.some((o) => o.group && o.group !== m.group);
        if (m.group && m.group !== lastGroup && (several || m.group.from || m.group.message)) {
          listEl.appendChild(deliveryHeader(m.group, several));
        }
        if (m.group) lastGroup = m.group;

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
        sub.textContent = m.contentType ? fmtSize(m.size) + ' · ' + m.contentType : fmtSize(m.size);
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

    async function showPublicLink(owner) {
      const field = document.getElementById('inbox-public-url');
      const copy = document.getElementById('inbox-public-copy');
      const publicId = batchRoot.getAttribute('data-public');
      if (!field || !publicId) return;
      const url = new URL('/r/' + publicId + '#' + E2E.b64uEncode(owner.shareSecret),
        location.href).toString();
      field.value = url;
      if (copy) copy.setAttribute('data-copy', url);
    }

    if (!E2E || !E2E.available || !ZIP) {
      fail(t('e2e_unsupported'));
      zipBtn.classList.add('btn-disabled');
    } else if (isInbox) {
      const secret = (location.hash || '').replace(/^#/, '');
      if (!/^[A-Za-z0-9_-]{43}$/.test(secret)) {
        keyMissing.hidden = false;
      } else if (!E2E.kemAvailable()) {
        fail(t('drop_kem_missing'));
      } else {
        const dropVersion = Number(batchRoot.getAttribute('data-version')) || 1;
        E2E.deriveDropOwnerKeys(E2E.b64uDecode(secret), dropVersion)
          .then(async (owner) => {
            kemSeed = owner.kemSeed;
            // The public link is derived from the private one, so an owner who
            // lost the link they handed out can produce it again here — from a
            // secret the server has never held either half of.
            await showPublicLink(owner);
            return startBatch();
          })
          .catch(() => fail(t('inbox_failed')));
      }
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

  // A v4 UUID, from crypto.getRandomValues where randomUUID is missing. Both
  // drop pages need one: a drop's public id and a submission's id are AADs, so
  // they are chosen by the party doing the sealing rather than by the server.
  function uuidV4() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' +
      h.slice(16, 20) + '-' + h.slice(20);
  }

  // ---- creating a drop -----------------------------------------------------
  //
  // The only page in the application that generates an asymmetric keypair, and
  // it does so here, in the tab, because that is the whole point: the server
  // must never hold the half that reads. What it is sent is a sealed public key
  // and a hash. What it is never sent is either fragment.

  const dropForm = document.getElementById('drop-form');
  if (dropForm) {
    const E2E = window.PYXIS_E2E;
    const createBtn = document.getElementById('drop-create');
    const statusEl = document.getElementById('drop-create-status');
    const errBox = document.getElementById('drop-error');
    const resultBox = document.getElementById('drop-result');
    const paramsBox = document.getElementById('drop-params');

    const el = (id) => document.getElementById(id);
    const fail = (msg) => {
      errBox.textContent = msg;
      errBox.hidden = false;
      statusEl.textContent = '';
    };

    // The presets write real numbers into the real fields, the way the
    // Single-Use preset on the upload page does. Nothing is hidden behind a
    // mode: what the drop will accept stays visible and editable.
    const presets = {
      'drop-preset-one': { files: '1', perSub: '1', subs: '1', hint: 'drops.preset_one_h' },
      'drop-preset-delivery': { files: '', perSub: '', subs: '1', hint: 'drops.preset_delivery_h' },
      'drop-preset-open': { files: '', perSub: '', subs: '', hint: 'drops.preset_open_h' },
    };
    const hintEl = document.getElementById('drop-preset-hint');
    for (const id of Object.keys(presets)) {
      const btn = el(id);
      if (!btn) continue;
      btn.addEventListener('click', () => {
        for (const other of Object.keys(presets)) {
          const b = el(other);
          if (b) b.setAttribute('aria-pressed', String(other === id));
        }
        el('drop-max-files').value = presets[id].files;
        el('drop-max-per-sub').value = presets[id].perSub;
        el('drop-max-subs').value = presets[id].subs;
        // The hints ride on the element as data attributes: the strings belong
        // to the page's catalogue, not to the JS one, and the CSP forbids an
        // inline script that could carry them.
        if (hintEl) hintEl.textContent = hintEl.getAttribute('data-' + id.replace('drop-preset-', '')) || '';
      });
    }

    const mbToBytes = (v) => {
      const n = parseInt(v, 10);
      return Number.isFinite(n) && n > 0 ? String(n * 1024 * 1024) : '';
    };

    if (createBtn) {
      createBtn.addEventListener('click', async () => {
        errBox.hidden = true;
        if (!E2E || !E2E.available) { fail(t('e2e_unsupported')); return; }
        if (!E2E.kemAvailable()) { fail(t('drop_kem_missing')); return; }
        createBtn.disabled = true;
        statusEl.textContent = t('drop_creating');
        try {
          // One secret, and everything else hangs off it: the KEM seed, the
          // public link's secret, the key that seals the public key and the
          // upload token. It exists in this tab and in the private link.
          const secret = E2E.randomBytes(E2E.KEY_LEN);
          const dropVersion = E2E.DROP_VERSION;
          const owner = await E2E.deriveDropOwnerKeys(secret, dropVersion);
          const share = await E2E.deriveDropShareKeys(owner.shareSecret, dropVersion);

          const body = new URLSearchParams();
          body.set('drop_version', String(dropVersion));
          body.set('kem_alg', window.PYXIS_KEM.ALG);
          body.set('label', el('drop-label').value.trim());
          body.set('note', el('drop-note').value.trim());
          body.set('expires_hours', el('drop-expires').value);
          body.set('max_files', el('drop-max-files').value.trim());
          body.set('max_files_per_submission', el('drop-max-per-sub').value.trim());
          body.set('max_submissions', el('drop-max-subs').value.trim());
          body.set('max_file_bytes', mbToBytes(el('drop-max-file-mb').value));
          body.set('max_total_bytes', mbToBytes(el('drop-max-total-mb').value));

          // The server is told the HASH of the upload token, never the token.
          // A drop's token is a standing write capability on the owner's
          // quota; there is no moment at which the server needs the value
          // itself, so it never gets it.
          const digest = await crypto.subtle.digest('SHA-256', share.token);
          body.set('upload_verifier', E2E.b64uEncode(new Uint8Array(digest)));

          const password = el('drop-password').value;
          if (password) {
            const salt = E2E.randomBytes(E2E.SALT_LEN);
            const derived = await E2E.derivePasswordKeys(password, salt, E2E.VERSION);
            body.set('auth_salt', E2E.b64uEncode(salt));
            body.set('auth_verifier', E2E.b64uEncode(derived.auth));
          }

          // Created first, sealed second: the public id is the sealed key's
          // AAD, so a drop has to exist before its key can be sealed to it.
          // The row is written with a placeholder and updated in the same
          // request — see the two-step POST below.
          const res = await fetch('/drops', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              Accept: 'application/json',
              'X-Requested-With': 'XMLHttpRequest',
            },
            body: await withSealedKey(body, owner, share),
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          const data = await res.json();

          const base = location.origin;
          const publicURL = base + data.uploadUrl + '#' + E2E.b64uEncode(owner.shareSecret);
          const privateURL = base + data.inboxUrl + '#' + E2E.b64uEncode(secret);

          el('drop-public-url').value = publicURL;
          el('drop-public-copy').setAttribute('data-copy', publicURL);
          el('drop-public-qr').setAttribute('data-qr-url', publicURL);
          el('drop-private-url').value = privateURL;
          el('drop-private-copy').setAttribute('data-copy', privateURL);
          el('drop-private-qr').setAttribute('data-qr-url', privateURL);
          el('drop-open-inbox').setAttribute('href', privateURL);

          resultBox.hidden = false;
          paramsBox.classList.add('step-locked');
          statusEl.textContent = t('drop_created');
          resultBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (err) {
          fail(t('drop_create_failed') + ' (' + err.message + ')');
        } finally {
          createBtn.disabled = false;
        }
      });
    }

    // The public id is the AAD of the sealed public key, and the id is the
    // server's to mint — so the key is sealed against an id chosen HERE and
    // sent with it. The server stores the id it was given rather than one of
    // its own, which is what keeps the AAD honest without a second round trip.
    async function withSealedKey(body, owner, share) {
      const publicId = uuidV4();
      const sealed = await E2E.sealDropPublicKey(share.pk, publicId, owner.publicKey);
      body.set('public_id', publicId);
      body.set('enc_pk', E2E.b64uEncode(sealed));
      return body.toString();
    }

  }

  // ---- sending files to a drop ---------------------------------------------
  //
  // No account, no session, and no way back: this page can seal files to the
  // recipient's key and nothing else. It cannot read what it just sent, what
  // anyone else sent, or how much is in the drop beyond what the page was told.

  const dropRoot = document.getElementById('drop-root');
  if (dropRoot) {
    const E2E = window.PYXIS_E2E;
    const publicId = dropRoot.getAttribute('data-public');
    const dropVersion = Number(dropRoot.getAttribute('data-version')) || 1;
    const maxUpload = Number(dropRoot.getAttribute('data-max-upload')) || 0;
    const maxFiles = Number(dropRoot.getAttribute('data-max-files')) || 0;
    const mode = dropRoot.getAttribute('data-mode');
    const errBox = document.getElementById('drop-error');
    const keyMissing = document.getElementById('key-missing');
    const zone = document.getElementById('drop-zone');
    const input = document.getElementById('drop-input');
    const queue = document.getElementById('drop-queue');
    const doneBox = document.getElementById('drop-done');
    const mainBox = document.getElementById('drop-main');

    let publicKey = null;   // the recipient's, opened from the sealed blob
    let uploadToken = null; // derived from this page's fragment
    let submission = null;  // { id, keys, roster, seq }
    let sent = 0;

    const fail = (msg) => {
      if (!errBox) return;
      errBox.textContent = msg;
      errBox.hidden = false;
    };

    const secret = (location.hash || '').replace(/^#/, '');

    async function unsealKey() {
      const share = await E2E.deriveDropShareKeys(E2E.b64uDecode(secret), dropVersion);
      uploadToken = share.token;
      const res = await fetch('/r/' + publicId + '/key', { headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      // If this throws, the served key was not sealed by whoever created this
      // link — a wrong link, or a substituted key. Either way nothing may be
      // encrypted to it, and the message says so in those terms.
      publicKey = await E2E.openDropPublicKey(share.pk, publicId, E2E.b64uDecode(data.encPk));
    }

    // One submission per visit: opened lazily with the first file, so a page
    // someone opened and closed again leaves no empty delivery behind.
    async function ensureSubmission() {
      if (submission) return submission;
      const { ct, ss } = E2E.dropEncapsulate(publicKey);
      const keys = await E2E.deriveSubmissionKeys(ss, ct, dropVersion);

      // The submission's id is generated HERE, for the same reason the drop's
      // public id is: it is the AAD of the sealed note and of every file's
      // manifest, so it has to exist before anything can be sealed against it.
      // The server takes the id it is given or refuses the request; it cannot
      // hand back a different one afterwards without breaking every seal.
      const id = uuidV4();
      const from = (document.getElementById('drop-from') || {}).value || '';
      const message = (document.getElementById('drop-message') || {}).value || '';

      const body = new URLSearchParams();
      body.set('token', E2E.b64uEncode(uploadToken));
      body.set('id', id);
      body.set('kem_ct', E2E.b64uEncode(ct));
      if (from || message) {
        body.set('enc_note', E2E.b64uEncode(
          await E2E.sealNote(keys.note, id, { from: from, message: message })));
      }

      const res = await fetch('/r/' + publicId + '/submissions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: body.toString(),
      });
      if (res.status === 409) throw new Error(t('drop_full'));
      if (res.status === 410) throw new Error(t('drop_closed'));
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      submission = { id: data.id, keys: keys, roster: [], seq: 0, ct: ct };
      return submission;
    }

    function row(file) {
      const li = document.createElement('li');
      li.className = 'queue-item';
      const info = document.createElement('div');
      info.className = 'queue-info';
      const name = document.createElement('span');
      name.className = 'queue-name';
      name.textContent = file.name;
      const status = document.createElement('span');
      status.className = 'queue-status';
      status.textContent = t('queued');
      info.appendChild(name);
      info.appendChild(status);
      const bar = document.createElement('div');
      bar.className = 'queue-bar';
      const fill = document.createElement('div');
      fill.className = 'queue-fill';
      bar.appendChild(fill);
      li.appendChild(info);
      li.appendChild(bar);
      queue.appendChild(li);
      return {
        li: li,
        set: (label, frac) => {
          status.textContent = frac === undefined ? label
            : label + ' ' + Math.round(Math.max(0, Math.min(1, frac)) * 100) + '%';
          if (frac !== undefined) fill.style.width = Math.round(frac * 100) + '%';
        },
        done: () => { li.classList.add('queue-done'); fill.style.width = '100%'; },
        failed: () => { li.classList.add('queue-failed'); },
      };
    }

    async function sendOne(file) {
      const ui = row(file);
      try {
        if (maxUpload > 0 && file.size > maxUpload) {
          ui.set(t('too_large', fmtSize(maxUpload)));
          ui.failed();
          return;
        }
        ui.set(t('drop_sealing'), 0);
        const sub = await ensureSubmission();

        const fileKeyRaw = E2E.randomBytes(E2E.KEY_LEN);
        const fileKey = await E2E.importAes(fileKeyRaw);
        const wrapped = await E2E.wrapFileKey(sub.keys.key, fileKeyRaw);
        const fileId = E2E.newFileId();
        const manifestBytes = E2E.buildManifest({
          id: fileId, batch: sub.id, size: file.size,
        });
        const encName = await E2E.sealName(sub.keys.name, fileId,
          { name: file.name, type: file.type || 'application/octet-stream' });
        const cipher = await E2E.encryptFile(file, fileKey, manifestBytes,
          (f) => ui.set(t('e2e_encrypting'), f));

        const form = new FormData();
        // Named after the id, never after the file: a multipart filename is
        // plaintext the server would otherwise see and log.
        form.append('file', cipher, fileId + '.enc');
        form.append('e2e', '1');
        form.append('e2e_version', String(E2E.VERSION));
        form.append('plain_size', String(file.size));
        form.append('manifest', E2E.b64uEncode(manifestBytes));
        form.append('enc_name', E2E.b64uEncode(encName));
        form.append('wrapped_key', E2E.b64uEncode(wrapped));

        ui.set(t('drop_sending'), 0);
        const url = '/r/' + publicId + '/upload?submission=' + encodeURIComponent(sub.id) +
          '&token=' + encodeURIComponent(E2E.b64uEncode(uploadToken));
        const res = await sendWithProgress(url, form, (f) => ui.set(t('drop_sending'), f));
        if (res.status === 409) { ui.set(t('drop_full')); ui.failed(); return; }
        if (res.status === 410) { ui.set(t('drop_closed')); ui.failed(); return; }
        if (res.status === 507) { ui.set(t('quota')); ui.failed(); return; }
        if (res.status < 200 || res.status >= 300) throw new Error('HTTP ' + res.status);

        const created = JSON.parse(res.text || '{}');
        sub.roster.push({
          id: created.id,
          name: file.name,
          size: file.size,
          type: file.type || 'application/octet-stream',
          manifest: await E2E.sha256b64u(manifestBytes),
        });
        sub.seq++;
        const sealedRoster = await E2E.sealRoster(sub.keys.roster, sub.id, {
          v: E2E.VERSION, batch: sub.id, seq: sub.seq, files: sub.roster,
        });
        const rbody = new URLSearchParams();
        rbody.set('token', E2E.b64uEncode(uploadToken));
        rbody.set('roster', E2E.b64uEncode(sealedRoster));
        rbody.set('seq', String(sub.seq));
        await fetch('/r/' + publicId + '/submissions/' + sub.id + '/roster', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest',
          },
          body: rbody.toString(),
        });

        ui.set(t('drop_sent'));
        ui.done();
        sent++;
        if (doneBox) doneBox.hidden = false;
      } catch (err) {
        ui.set(t('failed') + ': ' + err.message);
        ui.failed();
      }
    }

    // XHR rather than fetch, for the same reason the share uploader uses it:
    // upload progress. fetch still cannot report how much of a body has gone.
    function sendWithProgress(url, form, onProgress) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', url);
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable) onProgress(e.loaded / e.total);
        });
        xhr.addEventListener('load', () => resolve({ status: xhr.status, text: xhr.responseText }));
        xhr.addEventListener('error', () => reject(new Error(t('network'))));
        xhr.addEventListener('abort', () => reject(new Error(t('cancelled'))));
        xhr.send(form);
      });
    }

    let running = Promise.resolve();
    function enqueueFiles(list) {
      let files = Array.from(list || []);
      if (!files.length) return;
      if (maxFiles > 0 && sent + files.length > maxFiles) {
        // Refused here, before anything is encrypted, and the server enforces
        // the same number inside the transaction that books the upload.
        files = files.slice(0, Math.max(0, maxFiles - sent));
        fail(t('drop_file_limit', String(maxFiles)));
      }
      for (const f of files) {
        running = running.then(() => sendOne(f));
      }
    }

    if (zone && input) {
      zone.addEventListener('click', () => input.click());
      zone.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
      });
      input.addEventListener('change', () => { enqueueFiles(input.files); input.value = ''; });
      ['dragenter', 'dragover'].forEach((ev) => zone.addEventListener(ev, (e) => {
        e.preventDefault();
        zone.classList.add('dz-over');
      }));
      ['dragleave', 'drop'].forEach((ev) => zone.addEventListener(ev, (e) => {
        e.preventDefault();
        zone.classList.remove('dz-over');
      }));
      zone.addEventListener('drop', (e) => {
        if (e.dataTransfer) enqueueFiles(e.dataTransfer.files);
      });
    }

    async function start() {
      try {
        await unsealKey();
      } catch (err) {
        fail(t('drop_key_bad'));
        if (zone) zone.classList.add('dz-disabled');
        return;
      }
    }

    if (!E2E || !E2E.available) {
      fail(t('e2e_unsupported'));
    } else if (!E2E.kemAvailable()) {
      fail(t('drop_kem_missing'));
    } else if (!/^[A-Za-z0-9_-]{43}$/.test(secret)) {
      if (keyMissing) keyMissing.hidden = false;
      if (zone) zone.classList.add('dz-disabled');
    } else if (mode === 'password' && !dropRoot.getAttribute('data-unlocked')) {
      const pwInput = document.getElementById('drop-password');
      const unlockBtn = document.getElementById('drop-unlock');
      const lockBox = document.getElementById('drop-lock');
      const salt = E2E.b64uDecode(dropRoot.getAttribute('data-salt') || '');
      const unlock = async () => {
        if (!pwInput.value) return;
        unlockBtn.disabled = true;
        errBox.hidden = true;
        try {
          const derived = await E2E.derivePasswordKeys(pwInput.value, salt, E2E.VERSION);
          const res = await fetch('/r/' + publicId + '/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'auth=' + encodeURIComponent(E2E.b64uEncode(derived.auth)),
          });
          if (res.status === 429) { fail(t('rate_limited')); return; }
          if (!res.ok) { fail(t('e2e_wrong_pw')); pwInput.value = ''; return; }
          if (lockBox) lockBox.hidden = true;
          if (mainBox) mainBox.hidden = false;
          await start();
        } catch (err) {
          fail(t('e2e_failed') + ' (' + err.message + ')');
        } finally {
          unlockBtn.disabled = false;
        }
      };
      if (unlockBtn) unlockBtn.addEventListener('click', unlock);
      if (pwInput) pwInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
    } else if (dropRoot.getAttribute('data-open')) {
      start();
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

  function rememberName(id, name, type) {
    if (!id || !name) return;
    try {
      const store = readNameStore();
      // {n, t}; a bare string is what earlier versions wrote and is still read.
      store[id] = { n: name, t: type || '' };
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
      const entry = li && store[li.getAttribute('data-id')];
      if (!entry) continue;
      const name = typeof entry === 'string' ? entry : entry.n;
      const type = typeof entry === 'string' ? '' : entry.t;
      if (!name) continue;
      // The server sends the generic icon for a version 5 row, having no idea
      // what the file is. This browser does know, for its own uploads.
      const use = li.querySelector('.ficon-svg use');
      const icon = li.querySelector('.ficon');
      if (use && icon && (type || name)) {
        const kind = iconKindFor(type, name);
        use.setAttribute('href', '#fi-' + kind);
        icon.className = 'ficon ficon-' + kind;
      }
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
  const pasteBtn = document.getElementById('paste-btn');
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
    if (pasteBtn) pasteBtn.disabled = !paramsConfirmed;
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

  // ---- clipboard ----------------------------------------------------------
  //
  // Two ways in, because they see different clipboards. The paste event carries
  // whatever the OS actually put there — a screenshot, but also files copied in
  // a file manager, which arrive with their real names. The async Clipboard API
  // is the only path a button can take, and it exposes images alone. So Ctrl+V
  // is the capable route and the button is the discoverable one.

  const PASTE_EXT = {
    'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif',
    'image/webp': 'webp', 'image/avif': 'avif', 'image/bmp': 'bmp',
    'image/tiff': 'tif', 'image/svg+xml': 'svg',
    'application/pdf': 'pdf', 'text/plain': 'txt', 'text/html': 'html',
  };

  // Every browser hands a pasted screenshot over as "image.png", so a second
  // paste would queue a second file under the first one's name — and the name
  // is what the recipient sees, sealed but still the only label there is. A
  // timestamp makes it distinct and says where it came from; a file copied out
  // of a file manager already has a real name and keeps it.
  function pastedName(name, type, seq) {
    if (name && !/^(image|grafik|bild)\.\w+$/i.test(name)) return name;
    const d = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const stamp = d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) +
      '-' + pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds());
    const dot = name ? name.lastIndexOf('.') : -1;
    const ext = PASTE_EXT[type] || (dot > 0 ? name.slice(dot + 1) : 'bin');
    return 'pasted-' + stamp + (seq > 0 ? '-' + (seq + 1) : '') + '.' + ext;
  }

  // clipboardData.files is empty in some browsers that still list the same
  // entries under .items, so both are read and de-duplicated by identity.
  function filesFromClipboard(dt) {
    const out = [];
    for (const f of dt.files || []) out.push(f);
    for (const item of dt.items || []) {
      if (item.kind !== 'file') continue;
      const f = item.getAsFile();
      if (f && !out.includes(f)) out.push(f);
    }
    return out.map((f, i) => renamed(f, pastedName(f.name, f.type, i)));
  }

  // A File's name is read-only, so a rename means a new File over the same
  // bytes. type is carried across deliberately: it is sealed with the name and
  // decides the recipient's preview.
  function renamed(file, name) {
    if (name === file.name) return file;
    return new File([file], name, { type: file.type, lastModified: file.lastModified });
  }

  document.addEventListener('paste', (e) => {
    const dt = e.clipboardData;
    if (!dt) return;
    // Pasting text into a field stays a text paste, even when the clipboard
    // also carries an image — copying out of a rich editor usually gives both.
    const target = e.target;
    const editing = target && (target.isContentEditable ||
      /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName || ''));
    if (editing && (dt.getData('text/plain') || '') !== '') return;
    const files = filesFromClipboard(dt);
    if (!files.length) return;
    e.preventDefault();
    if (handleFiles(files)) toast(t('pasted', fileCountLabel(files.length)));
  });

  if (pasteBtn) {
    pasteBtn.addEventListener('click', async () => {
      // navigator.clipboard is absent on an insecure origin, which is also
      // where the upload itself cannot run — see the E2E guard.
      if (!navigator.clipboard || !navigator.clipboard.read) {
        toast(t('paste_unsupported'));
        return;
      }
      let items;
      try {
        items = await navigator.clipboard.read();
      } catch (err) {
        // A denied permission and a dismissed paste prompt both land here;
        // Ctrl+V needs neither, so that is what the message points at.
        toast(t(err && err.name === 'NotAllowedError' ? 'paste_denied' : 'paste_empty'));
        return;
      }
      const files = [];
      for (const item of items) {
        // Plain text and HTML are the flavours of a text copy, not a file.
        const type = (item.types || []).find(
          (ty) => ty !== 'text/plain' && ty !== 'text/html');
        if (!type) continue;
        try {
          const blob = await item.getType(type);
          files.push(new File([blob], pastedName('', type, files.length), { type }));
        } catch (err) { /* skip the entry, keep the rest of the clipboard */ }
      }
      if (!files.length) {
        toast(t('paste_empty'));
        return;
      }
      if (handleFiles(files)) toast(t('pasted', fileCountLabel(files.length)));
    });
  }

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

  // Returns whether the files were accepted: a paste confirms itself with a
  // toast, and must not claim to have added anything the gate turned away.
  function handleFiles(files) {
    if (!files || files.length === 0) return false;
    // A drop lands on the dropzone whether or not its input is disabled, so
    // the gate is enforced here too rather than by the styling alone.
    if (!paramsConfirmed) {
      toast(t('upload.step2_locked'));
      if (stepParams) stepParams.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      return false;
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
    return true;
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
    // Worth offering: by the time someone reads the message and taps it, the
    // file may well have finished coming down from iCloud.
    file_gone: true,
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
    } catch (err) {
      if (err && err.name === 'AbortError') return; // cancel handler already rendered
      // A file the browser will no longer read is not a broken cipher, and
      // saying "Encryption failed: The object cannot be found here" sent
      // people looking in the wrong place. readSlice in e2e.js has already
      // retried it several times, so this is the settled answer.
      if (err && err.code === 'file-unreadable') {
        fail('file_gone', t('reason_file_gone'));
        return;
      }
      fail('e2e_failed', t('reason_encrypt', (err && err.message) || String(err)));
      return;
    }
    if (ctl.aborted) return;

    // The ciphertext is finished by this point, so a lost connection costs
    // only the transfer — and losing one is routine on a phone or tablet:
    // iOS suspends a backgrounded tab, a Wi-Fi handover drops the socket, and
    // a long body can outlive the proxy's patience. Each of those surfaced as
    // "the connection was interrupted" and a Retry button, in the middle of a
    // queue the user had walked away from.
    //
    // So the send is retried a couple of times on its own. The upload is NOT
    // encrypted again: the ciphertext blob is already in hand, and re-reading
    // the File is the very step that fails on an iCloud-backed file (see
    // readSlice in e2e.js).
    const NET_ATTEMPTS = 3;
    const RETRY_WAIT = [2000, 6000];
    // A proxy that gave up on a body it was still reading answers 502/503/504,
    // which from here is the same event as a dead socket. Every other status
    // is the server's considered answer and is reported as it stands.
    const RETRY_STATUS = { 502: true, 503: true, 504: true };
    let attempt = 0;

    // retryOrFail schedules the next attempt, or gives up and leaves the row
    // with its explanation and a manual Retry button.
    function retryOrFail(kind, detail) {
      if (ctl.aborted) return;
      if (attempt >= NET_ATTEMPTS) {
        fail(kind, detail);
        return;
      }
      status.textContent = t('retrying');
      fill.style.width = '0%';
      reason.textContent = t('reason_retrying', attempt + 1, NET_ATTEMPTS);
      reason.hidden = false;
      setTimeout(() => {
        if (!ctl.aborted) sendAttempt();
      }, RETRY_WAIT[Math.min(attempt - 1, RETRY_WAIT.length - 1)]);
    }

    function sendAttempt() {
      attempt++;
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
          // A retry notice from an earlier attempt has been overtaken.
          reason.textContent = '';
          reason.hidden = true;
          // The stored bytes have just changed, so the shell's storage bars
          // are now out of date. Coalesced: a whole drop costs one request.
          refreshStorageBars();
          // No per-file link: the batch link covers every file in this visit.
          batchState.count++;
          renderBatchPanel();
          let created = null;
          try { created = JSON.parse(xhr.responseText); } catch (e) { /* handled below */ }
          if (created && created.id) {
            // This browser sealed the name a moment ago, so it is the one place
            // that can still read it without the link.
            rememberName(created.id, file.name, file.type || 'application/octet-stream');
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
        } else if (RETRY_STATUS[xhr.status]) {
          retryOrFail('network', serverReason());
        } else {
          fail('failed', serverReason());
        }
      };
      xhr.onerror = () => {
        if (ctl.aborted) return;
        retryOrFail('network', t('reason_network'));
      };
      xhr.send(fd);
    }

    sendAttempt();
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
