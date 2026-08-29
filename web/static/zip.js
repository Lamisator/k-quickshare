// Minimal ZIP writer for Pyxis batch downloads.
//
// The server stores ciphertext and holds no keys, so it cannot zip a batch —
// only the browser can, after decrypting each member locally. This builds a
// standard ZIP entirely client-side.
//
// STORE only (no DEFLATE). Batch members are already-encrypted blobs decrypted
// in this tab, and the common payload — images, video, PDFs, archives — barely
// compresses, so DEFLATE would double peak memory to save very little. The
// entries go in uncompressed and the archive is the sum of its parts.
//
// No ZIP64: offsets and sizes are 32-bit, so an archive must stay under 4 GiB.
// build() refuses past that rather than emitting a file that appears to work
// and unpacks to garbage; the caller is expected to offer per-file downloads
// instead.
(function () {
  'use strict';

  const MAX32 = 0xffffffff;
  const LOCAL_SIG = 0x04034b50;
  const CENTRAL_SIG = 0x02014b50;
  const EOCD_SIG = 0x06054b50;
  const UTF8_FLAG = 0x0800; // names are UTF-8, not CP437
  const CRC_SLICE = 1 << 20;

  const crcTable = (function () {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[i] = c >>> 0;
    }
    return t;
  })();

  function crcUpdate(crc, bytes) {
    let c = crc;
    for (let i = 0; i < bytes.length; i++) c = crcTable[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    return c >>> 0;
  }

  // CRC a Blob without ever holding a second full copy of it: read it back in
  // slices, so peak memory stays at one slice regardless of file size.
  async function crcOfBlob(blob) {
    let crc = 0xffffffff;
    for (let off = 0; off < blob.size; off += CRC_SLICE) {
      const buf = await blob.slice(off, Math.min(off + CRC_SLICE, blob.size)).arrayBuffer();
      crc = crcUpdate(crc, new Uint8Array(buf));
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  // MS-DOS packed date/time, the only timestamp a base ZIP record carries.
  function dosDateTime(d) {
    const year = Math.max(1980, d.getFullYear());
    return {
      time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
      date: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
    };
  }

  // Zip entries are keyed by name, so duplicates would silently overwrite each
  // other on extraction. Two files legitimately called "scan.pdf" become
  // "scan.pdf" and "scan (2).pdf".
  function uniqueNames(entries) {
    const seen = Object.create(null);
    return entries.map((e) => {
      let name = String(e.name || 'file').replace(/[\\/]+/g, '_').replace(/^\.+/, '');
      if (!name) name = 'file';
      if (seen[name] === undefined) {
        seen[name] = 1;
        return name;
      }
      const dot = name.lastIndexOf('.');
      const stem = dot > 0 ? name.slice(0, dot) : name;
      const ext = dot > 0 ? name.slice(dot) : '';
      let n = ++seen[name];
      let candidate = stem + ' (' + n + ')' + ext;
      while (seen[candidate] !== undefined) {
        n++;
        candidate = stem + ' (' + n + ')' + ext;
      }
      seen[name] = n;
      seen[candidate] = 1;
      return candidate;
    });
  }

  // build assembles [{name, blob}] into a single ZIP Blob.
  //
  // Data blobs are handed to the Blob constructor by reference rather than
  // concatenated into one big array, so the browser can keep them backed by
  // disk instead of forcing the whole archive into RAM.
  async function build(entries, onProgress) {
    const te = new TextEncoder();
    const names = uniqueNames(entries);
    const stamp = dosDateTime(new Date());
    const parts = [];
    const central = [];
    let offset = 0;

    for (let i = 0; i < entries.length; i++) {
      const blob = entries[i].blob;
      const nameBytes = te.encode(names[i]);
      const size = blob.size;
      if (size > MAX32 || offset + 30 + nameBytes.length + size > MAX32) {
        throw tooBig();
      }
      const crc = await crcOfBlob(blob);

      const local = new Uint8Array(30 + nameBytes.length);
      const lv = new DataView(local.buffer);
      lv.setUint32(0, LOCAL_SIG, true);
      lv.setUint16(4, 20, true);          // version needed
      lv.setUint16(6, UTF8_FLAG, true);
      lv.setUint16(8, 0, true);           // method: store
      lv.setUint16(10, stamp.time, true);
      lv.setUint16(12, stamp.date, true);
      lv.setUint32(14, crc, true);
      lv.setUint32(18, size, true);       // compressed == uncompressed
      lv.setUint32(22, size, true);
      lv.setUint16(26, nameBytes.length, true);
      lv.setUint16(28, 0, true);          // no extra field
      local.set(nameBytes, 30);

      parts.push(local, blob);

      const cd = new Uint8Array(46 + nameBytes.length);
      const cv = new DataView(cd.buffer);
      cv.setUint32(0, CENTRAL_SIG, true);
      cv.setUint16(4, 20, true);          // version made by
      cv.setUint16(6, 20, true);          // version needed
      cv.setUint16(8, UTF8_FLAG, true);
      cv.setUint16(10, 0, true);
      cv.setUint16(12, stamp.time, true);
      cv.setUint16(14, stamp.date, true);
      cv.setUint32(16, crc, true);
      cv.setUint32(20, size, true);
      cv.setUint32(24, size, true);
      cv.setUint16(28, nameBytes.length, true);
      cv.setUint32(42, offset, true);     // local header offset
      cd.set(nameBytes, 46);
      central.push(cd);

      offset += local.length + size;
      if (onProgress) onProgress(i + 1, entries.length);
    }

    let cdSize = 0;
    for (const cd of central) cdSize += cd.length;
    if (offset + cdSize + 22 > MAX32) throw tooBig();

    const eocd = new Uint8Array(22);
    const ev = new DataView(eocd.buffer);
    ev.setUint32(0, EOCD_SIG, true);
    ev.setUint16(8, central.length, true);
    ev.setUint16(10, central.length, true);
    ev.setUint32(12, cdSize, true);
    ev.setUint32(16, offset, true);

    return new Blob(parts.concat(central, [eocd]), { type: 'application/zip' });
  }

  function tooBig() {
    const err = new Error('archive exceeds the 4 GiB ZIP limit');
    err.name = 'ZipTooLargeError';
    return err;
  }

  window.PYXIS_ZIP = { build: build, MAX_BYTES: MAX32 };
})();
