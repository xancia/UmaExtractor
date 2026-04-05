# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
"""
Uma Musume API Discovery Tool
================================
Captures ALL API responses and discovers new MsgPack structures in memory.
No filtering — saves everything so you can find what you're looking for.

Strategies:
  1. SSL/HTTP hooking — saves every API response body to disk
  2. Broad MsgPack key discovery — diffs memory before/after for any new
     MsgPack key names (not just a hardcoded list)
  3. Full memory key-name dump — re-runs explore_memory-style scan after
     button tap and saves everything new

Usage:
  python intercept_api.py                      # live capture
  python intercept_api.py --analyze <file>     # re-analyze a .msgpack blob
"""
import gzip
import json
import os
import sys
import time
import traceback
import logging

import frida
import msgpack

# ── Config ─────────────────────────────────────────────────────────────────

TARGET_PROCESS_NAMES = [
    "UmamusumePrettyDerby.exe",
    "UmamusumePrettyDerby",
]
PROCESS_KEYWORDS = ["uma", "musume", "derby", "cygames"]
MAX_WAIT_SECONDS = 600

# These are skill IDs visible on the acquire screen — used only for
# flagging interesting results, NOT for filtering.  Everything is saved.
KNOWN_SKILL_IDS = {200154, 200152, 200441, 200652, 200722, 201152}

PII_FIELDS = ["viewer_id", "owner_viewer_id", "dmm_viewer_id"]

# ── Logging ────────────────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(_SCRIPT_DIR, "intercept_debug.log")
OUTPUT_DIR = os.path.join(_SCRIPT_DIR, "intercepted_responses")

os.makedirs(OUTPUT_DIR, exist_ok=True)

logger = logging.getLogger("intercept")
logger.setLevel(logging.DEBUG)

_fh = logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8")
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_fh)

_ch = logging.StreamHandler(sys.stdout)
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_ch)


def log(msg="", level="info"):
    getattr(logger, level)(str(msg))


def log_debug(msg=""):
    logger.debug(str(msg))


# ── Frida JS Script ───────────────────────────────────────────────────────

FRIDA_SCRIPT = r"""
(function() {
    const scanProtection = "rw-";
    const minRangeSize = 16 * 1024;
    const maxRangeSize = 500 * 1024 * 1024;

    function hex(b) { return ('0' + b.toString(16).toUpperCase()).slice(-2); }

    // ════════════════════════════════════════════════════════════════════
    // STRATEGY 1: Hook SSL/HTTP — capture EVERY response
    // ════════════════════════════════════════════════════════════════════

    let sslHooked = false;
    let networkChunks = 0;

    function tryHookSSL() {
        const sslLibNames = [
            'libssl-3.dll', 'libssl-1_1.dll', 'libssl.dll',
            'ssl.dll', 'ssleay32.dll',
            'GameAssembly.dll', 'UnityPlayer.dll',
            'libcrypto-3.dll', 'libcrypto-1_1.dll',
        ];
        const sslFuncNames = ['SSL_read', 'ssl3_read_internal', 'ssl_read_internal'];

        // List all modules for diagnostics
        const allMods = Process.enumerateModules();
        const modNames = allMods.map(m => m.name).sort();
        console.log(`[SSL] ${allMods.length} modules loaded: ${modNames.slice(0, 30).join(', ')}...`);

        for (const libName of sslLibNames) {
            let mod;
            try { mod = Process.getModuleByName(libName); } catch(e) { continue; }
            console.log(`[SSL] Found module: ${libName} (base: ${mod.base}, size: ${mod.size})`);

            for (const funcName of sslFuncNames) {
                let addr;
                try { addr = Module.findExportByName(libName, funcName); } catch(e) { continue; }
                if (!addr) continue;

                console.log(`[SSL] Hooking ${funcName} at ${addr}`);
                try {
                    Interceptor.attach(addr, {
                        onEnter(args) {
                            this.ssl = args[0];
                            this.buf = args[1];
                            this.num = args[2].toInt32();
                        },
                        onLeave(retval) {
                            const bytesRead = retval.toInt32();
                            if (bytesRead <= 0) return;
                            try {
                                const data = this.buf.readByteArray(bytesRead);
                                networkChunks++;
                                send({ type: 'ssl_data', size: bytesRead,
                                       ssl_ptr: this.ssl.toString(),
                                       chunk_num: networkChunks }, data);
                            } catch(e) {}
                        }
                    });
                    sslHooked = true;
                    console.log(`[SSL] OK — hooked ${funcName} in ${libName}`);
                    return true;
                } catch(e) {
                    console.log(`[SSL] Failed: ${e}`);
                }
            }
        }

        // WinHTTP / WinInet fallback
        for (const lib of ['winhttp.dll', 'wininet.dll']) {
            const funcName = lib === 'winhttp.dll' ? 'WinHttpReadData' : 'InternetReadFile';
            let readFunc;
            try { readFunc = Module.findExportByName(lib, funcName); } catch(e) { continue; }
            if (!readFunc) continue;

            console.log(`[HTTP] Hooking ${funcName} in ${lib}`);
            try {
                Interceptor.attach(readFunc, {
                    onEnter(args) {
                        this.buf = args[1];
                        this.bytesReadPtr = args[3];
                    },
                    onLeave(retval) {
                        if (retval.toInt32() === 0) return;
                        try {
                            const n = this.bytesReadPtr.readU32();
                            if (n <= 0) return;
                            networkChunks++;
                            send({ type: 'http_data', size: n, chunk_num: networkChunks },
                                 this.buf.readByteArray(n));
                        } catch(e) {}
                    }
                });
                sslHooked = true;
                console.log(`[HTTP] OK — hooked ${funcName}`);
            } catch(e) {
                console.log(`[HTTP] Failed: ${e}`);
            }
        }

        return sslHooked;
    }

    // ════════════════════════════════════════════════════════════════════
    // STRATEGY 2: Broad MsgPack key-name discovery
    // Scan for common MsgPack key suffixes (_array, _list, _data, _info,
    // _id, etc.) and capture ALL matches — not a hardcoded key list.
    // ════════════════════════════════════════════════════════════════════

    const suffixPatterns = [
        { name: "_array",  hex: "5F 61 72 72 61 79" },
        { name: "_list",   hex: "5F 6C 69 73 74" },
        { name: "_data",   hex: "5F 64 61 74 61" },
        { name: "_info",   hex: "5F 69 6E 66 6F" },
        { name: "_num",    hex: "5F 6E 75 6D" },
        { name: "_type",   hex: "5F 74 79 70 65" },
        { name: "_count",  hex: "5F 63 6F 75 6E 74" },
        { name: "_flag",   hex: "5F 66 6C 61 67" },
        { name: "_status", hex: "5F 73 74 61 74 75 73" },
        { name: "_result", hex: "5F 72 65 73 75 6C 74" },
        { name: "_skill",  hex: "5F 73 6B 69 6C 6C" },
        { name: "skill_",  hex: "73 6B 69 6C 6C 5F" },
    ];

    function readKeyNameAt(address, range) {
        // Walk backward from suffix match to find the MsgPack fixstr marker
        // fixstr: 0xA0-0xBF (length 0-31 encoded in low 5 bits)
        try {
            const maxBack = 40;
            const startOff = address.sub(range.base).toInt32();
            const lookBack = Math.min(maxBack, startOff);
            if (lookBack <= 0) return null;
            const buf = address.sub(lookBack).readByteArray(lookBack);
            const view = new Uint8Array(buf);
            // Search backward for a fixstr marker whose length matches
            for (let i = view.length - 1; i >= 0; i--) {
                const b = view[i];
                if (b >= 0xA0 && b <= 0xBF) {
                    const strLen = b & 0x1F;
                    const expectedEnd = i + 1 + strLen;
                    // The suffix match address should be within this string
                    if (expectedEnd >= view.length && expectedEnd <= view.length + 40) {
                        const strBytes = address.sub(lookBack - i - 1).readByteArray(strLen);
                        const arr = new Uint8Array(strBytes);
                        let s = '';
                        for (let j = 0; j < arr.length; j++) s += String.fromCharCode(arr[j]);
                        return { name: s, markerAddr: address.sub(lookBack - i) };
                    }
                }
                // str8: D9 len
                if (b === 0xD9 && i + 1 < view.length) {
                    const strLen = view[i + 1];
                    if (strLen > 0 && strLen <= 255) {
                        const expectedEnd = i + 2 + strLen;
                        if (expectedEnd >= view.length && expectedEnd <= view.length + 40) {
                            const strBytes = address.sub(lookBack - i - 2).readByteArray(strLen);
                            const arr = new Uint8Array(strBytes);
                            let s = '';
                            for (let j = 0; j < arr.length; j++) s += String.fromCharCode(arr[j]);
                            return { name: s, markerAddr: address.sub(lookBack - i) };
                        }
                    }
                }
            }
        } catch(e) {}
        return null;
    }

    function discoverAllKeys() {
        const ranges = Process.enumerateRanges({protection: scanProtection, coalesce: true})
            .filter(r => r.size >= minRangeSize && r.size <= maxRangeSize);

        // key name -> Set of address strings
        const keyHits = {};
        // key name -> { rangeBase, rangeSize } of first hit
        const keyMeta = {};

        for (const suffix of suffixPatterns) {
            for (const range of ranges) {
                try {
                    const results = Memory.scanSync(range.base, range.size, suffix.hex);
                    for (const r of results) {
                        const info = readKeyNameAt(r.address, range);
                        if (!info) continue;
                        const name = info.name;
                        // Filter out obviously non-key strings
                        if (name.length < 3 || name.length > 60) continue;
                        if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) continue;
                        if (!keyHits[name]) {
                            keyHits[name] = new Set();
                            keyMeta[name] = { rangeBase: range.base, rangeSize: range.size };
                        }
                        keyHits[name].add(r.address.toString());
                    }
                } catch(e) {}
            }
        }

        return { keyHits, keyMeta };
    }

    // ════════════════════════════════════════════════════════════════════
    // Run
    // ════════════════════════════════════════════════════════════════════

    console.log("=== Uma Musume API Discovery Tool ===");
    console.log("Phase 1: Baseline scan...");

    const baseline = discoverAllKeys();
    const baselineKeys = Object.keys(baseline.keyHits);
    const baselineAddrCount = Object.values(baseline.keyHits)
        .reduce((s, set) => s + set.size, 0);
    console.log(`Baseline: ${baselineKeys.length} unique key names, ${baselineAddrCount} total hits`);

    // Send baseline summary
    const baselineSummary = {};
    for (const [name, addrs] of Object.entries(baseline.keyHits)) {
        baselineSummary[name] = addrs.size;
    }
    send({ type: 'baseline_keys', keys: baselineSummary });

    console.log("Phase 2: Installing network hooks...");
    const hooked = tryHookSSL();

    console.log("Baseline complete.");
    send({ type: 'ready', ssl_hooked: hooked,
           baseline_key_count: baselineKeys.length,
           baseline_addr_count: baselineAddrCount });

    // Poll for new keys every 2 seconds
    let scanCount = 0;
    let alreadySentNewKeys = new Set();

    setInterval(() => {
        scanCount++;

        const current = discoverAllKeys();

        // Find keys that are NEW or have NEW addresses
        const newKeyData = [];
        for (const [name, addrs] of Object.entries(current.keyHits)) {
            const baseAddrs = baseline.keyHits[name];
            let newAddrs;
            if (!baseAddrs) {
                // Entirely new key name
                newAddrs = addrs;
            } else {
                // Check for new addresses under an existing key
                newAddrs = new Set();
                for (const a of addrs) {
                    if (!baseAddrs.has(a)) newAddrs.add(a);
                }
            }

            if (newAddrs.size > 0 && !alreadySentNewKeys.has(name)) {
                alreadySentNewKeys.add(name);
                newKeyData.push({
                    name: name,
                    isNewKey: !baseAddrs,
                    newAddrCount: newAddrs.size,
                    totalAddrCount: addrs.size,
                    meta: current.keyMeta[name]
                });
            }
        }

        if (newKeyData.length > 0) {
            console.log(`[DISC] Found ${newKeyData.length} new/changed key names!`);

            // For each new key, read a blob around it for Python-side analysis
            for (const kd of newKeyData) {
                console.log(`  NEW: "${kd.name}" (${kd.isNewKey ? 'brand new' : 'new addrs'}, ${kd.newAddrCount} hits)`);

                // Find one of the new addresses to read around
                const addrs = current.keyHits[kd.name];
                const baseAddrs = baseline.keyHits[kd.name] || new Set();
                let targetAddr = null;
                for (const a of addrs) {
                    if (!baseAddrs.has(a)) {
                        targetAddr = ptr(a);
                        break;
                    }
                }
                if (!targetAddr) {
                    // Use any address
                    targetAddr = ptr(addrs.values().next().value);
                }

                // Read 256KB before and 5MB after to capture the containing structure
                const meta = kd.meta;
                const readBefore = 256 * 1024;
                const readAfter = 5 * 1024 * 1024;
                const readStart = targetAddr.sub(readBefore);
                const clampedStart = readStart.compare(meta.rangeBase) < 0
                    ? meta.rangeBase : readStart;
                const maxFromRange = meta.rangeSize -
                    clampedStart.sub(meta.rangeBase).toInt32();
                const maxRead = Math.min(readBefore + readAfter, maxFromRange, 25 * 1024 * 1024);
                if (maxRead <= 0) continue;

                try {
                    const data = clampedStart.readByteArray(maxRead);
                    const hitOffset = targetAddr.sub(clampedStart).toInt32();
                    send({
                        type: 'discovery_blob',
                        key_name: kd.name,
                        is_new_key: kd.isNewKey,
                        new_addr_count: kd.newAddrCount,
                        read_size: maxRead,
                        key_offset: hitOffset
                    }, data);
                } catch(e) {
                    console.log(`  Failed to read around "${kd.name}": ${e}`);
                }
            }
        }

        if (scanCount % 15 === 0) {
            send({ type: 'tick', seconds: scanCount * 2,
                   network_chunks: networkChunks,
                   new_keys_found: alreadySentNewKeys.size });
        }
    }, 2000);
})();
"""


# ── Process attachment ─────────────────────────────────────────────────────

def find_candidate_processes():
    try:
        device = frida.get_local_device()
        processes = device.enumerate_processes()
    except Exception as e:
        log(f"[!] Could not enumerate processes: {e}")
        return []
    candidates = []
    for proc in processes:
        name = (proc.name or "").lower()
        if any(kw in name for kw in PROCESS_KEYWORDS):
            candidates.append(proc)
    candidates.sort(key=lambda p: (p.name or "").lower())
    return candidates


def attach_to_game():
    attach_errors = []
    for process_name in TARGET_PROCESS_NAMES:
        try:
            session = frida.attach(process_name)
            log(f"[OK] Attached: {process_name}")
            return session
        except Exception as e:
            attach_errors.append((process_name, e))

    candidates = find_candidate_processes()
    if candidates:
        log("[!] Default name failed. Found similar processes:")
        for proc in candidates[:10]:
            log(f"    - {proc.name} (pid {proc.pid})")
        for proc in candidates:
            try:
                session = frida.attach(proc.pid)
                log(f"[OK] Attached: {proc.name} (pid {proc.pid})")
                return session
            except Exception as e:
                attach_errors.append((f"{proc.name} (pid {proc.pid})", e))

    log("[X] Could not attach to game process.")
    for target, err in attach_errors:
        log(f"    - {target}: {type(err).__name__}: {err}")
    return None


# ── MsgPack helpers ────────────────────────────────────────────────────────

def try_decode_msgpack(data):
    """Try to decode bytes as MsgPack. Returns (decoded, offset) or None."""
    # Try gzip first
    if data[:2] == b'\x1f\x8b':
        try:
            data = gzip.decompress(data)
        except Exception:
            pass

    # Try at offset 0
    try:
        decoded = msgpack.unpackb(data, raw=False)
        if isinstance(decoded, (dict, list)) and len(decoded) > 0:
            return decoded, 0
    except Exception:
        pass

    # Try first 64 offsets
    for off in range(1, min(64, len(data))):
        try:
            decoded = msgpack.unpackb(data[off:], raw=False)
            if isinstance(decoded, (dict, list)) and len(decoded) > 0:
                return decoded, off
        except Exception:
            continue

    return None


def find_msgpack_at_key(raw_bytes, key_offset):
    """Given raw bytes and the offset where a key name was found,
    try to find and decode the containing MsgPack structure."""
    results = []

    # Strategy: walk backward from the key to find a map/array header
    search_start = max(0, key_offset - 2 * 1024 * 1024)
    for back in range(key_offset, search_start, -1):
        b = raw_bytes[back]
        # map headers: fixmap 0x80-0x8F, map16 0xDE, map32 0xDF
        # array headers: fixarray 0x90-0x9F, array16 0xDC, array32 0xDD
        if not (0x80 <= b <= 0x9F or b in (0xDC, 0xDD, 0xDE, 0xDF)):
            continue
        try:
            chunk = raw_bytes[back:min(back + 25 * 1024 * 1024, len(raw_bytes))]
            unpacker = msgpack.Unpacker(raw=False, max_buffer_size=50 * 1024 * 1024)
            unpacker.feed(chunk)
            decoded = unpacker.unpack()
            if decoded is None:
                continue
            if isinstance(decoded, (list, dict)) and len(decoded) == 0:
                continue
            consumed = unpacker.tell()
            # The decoded structure must span past the key offset
            if back + consumed > key_offset:
                desc = f"{'map' if isinstance(decoded, dict) else 'array'}[{len(decoded)}]"
                results.append({
                    "offset": back,
                    "description": desc,
                    "data": decoded,
                    "consumed": consumed,
                })
                # If we found a big structure, that's probably the one
                if consumed > 1024:
                    break
        except Exception:
            continue

    return results


def deep_find_skill_ids(obj, depth=0):
    """Walk a decoded MsgPack structure and collect all integers that look
    like skill IDs (in the 100000-999999 range)."""
    found = set()
    if depth > 30:
        return found
    if isinstance(obj, int) and 100000 <= obj <= 999999:
        found.add(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, int) and 100000 <= k <= 999999:
                found.add(k)
            found |= deep_find_skill_ids(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            found |= deep_find_skill_ids(item, depth + 1)
    return found


def strip_pii(data):
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for pii in PII_FIELDS:
                    item.pop(pii, None)
    elif isinstance(data, dict):
        for pii in PII_FIELDS:
            data.pop(pii, None)
        for v in data.values():
            if isinstance(v, dict):
                for pii in PII_FIELDS:
                    v.pop(pii, None)


def summarize_decoded(data, label=""):
    """Log a short summary of a decoded MsgPack structure."""
    if isinstance(data, dict):
        keys = list(data.keys())[:25]
        log(f"  {label}map with {len(data)} keys: {keys}")
        for k in keys[:8]:
            v = data[k]
            if isinstance(v, list):
                sub = ""
                if v and isinstance(v[0], dict):
                    sub = f", item keys: {list(v[0].keys())[:8]}"
                log(f"    {k}: array[{len(v)}]{sub}")
            elif isinstance(v, dict):
                log(f"    {k}: map[{len(v)} keys]")
            elif isinstance(v, (int, float, bool)):
                log(f"    {k}: {v}")
            elif isinstance(v, str) and len(v) < 80:
                log(f"    {k}: \"{v}\"")
    elif isinstance(data, list):
        log(f"  {label}array with {len(data)} items")
        if data and isinstance(data[0], dict):
            log(f"    item[0] keys: {list(data[0].keys())[:12]}")


# ── HTTP response reassembly ──────────────────────────────────────────────

class HttpResponseAssembler:
    """Reassemble HTTP responses from raw SSL_read chunks."""

    def __init__(self):
        self.streams = {}   # ssl_ptr -> bytearray
        self.responses = []
        self.raw_chunks = []  # fallback: save raw chunks too

    def feed(self, ssl_ptr, data):
        if ssl_ptr not in self.streams:
            self.streams[ssl_ptr] = bytearray()
        buf = self.streams[ssl_ptr]
        buf.extend(data)

        # Also accumulate raw chunks for brute-force MsgPack scanning
        self.raw_chunks.append(bytes(data))

        while True:
            response = self._try_extract(buf)
            if response is None:
                break
            self.responses.append(response)

    def _try_extract(self, buf):
        header_end = buf.find(b'\r\n\r\n')
        if header_end == -1:
            # Not HTTP framed — try treating accumulated data as raw body
            if len(buf) > 512 and not buf[:5].startswith(b'HTTP/'):
                data = bytes(buf)
                buf.clear()
                return {"body": data, "headers": {}, "raw": True}
            return None

        body_start = header_end + 4
        try:
            header_str = buf[:header_end].decode('latin-1')
        except Exception:
            buf.clear()
            return None

        headers = {}
        lines = header_str.split('\r\n')
        status_line = lines[0] if lines else ""
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()

        content_length = int(headers.get('content-length', -1))

        if content_length >= 0:
            total = body_start + content_length
            if len(buf) < total:
                return None
            body = bytes(buf[body_start:total])
            del buf[:total]
            return {"body": body, "headers": headers, "status": status_line}

        if 'chunked' in headers.get('transfer-encoding', ''):
            parts = []
            pos = body_start
            while pos < len(buf):
                end = buf.find(b'\r\n', pos)
                if end == -1:
                    return None
                try:
                    sz = int(buf[pos:end], 16)
                except ValueError:
                    buf.clear()
                    return None
                if sz == 0:
                    del buf[:end + 4]
                    return {"body": b''.join(parts), "headers": headers,
                            "status": status_line}
                ds = end + 2
                de = ds + sz
                if de + 2 > len(buf):
                    return None
                parts.append(bytes(buf[ds:de]))
                pos = de + 2
            return None

        # No content-length, no chunked
        if len(buf) > body_start + 64:
            data = bytes(buf[body_start:])
            buf.clear()
            return {"body": data, "headers": headers, "status": status_line}
        return None

    def get_new_responses(self):
        r = self.responses[:]
        self.responses.clear()
        return r

    def get_raw_chunks(self):
        r = self.raw_chunks[:]
        self.raw_chunks.clear()
        return r


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("  Uma Musume API Discovery Tool")
    log("  Captures ALL API traffic + memory diffs")
    log("=" * 60)
    log()
    log("  INSTRUCTIONS:")
    log("  1. Be on the screen BEFORE the action you want to capture")
    log("  2. Press Enter to start the baseline scan")
    log("  3. Wait for 'BASELINE DONE'")
    log("  4. Perform the in-game action (tap button etc.)")
    log("  5. Wait ~10-15 seconds, then Ctrl+C")
    log("  6. Inspect intercepted_responses/ for all captured data")
    log()

    input("  >>> Press Enter to start baseline... ")
    log()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    assembler = HttpResponseAssembler()
    captured_files = []
    net_response_count = 0
    discovery_blob_count = 0
    script_error = None
    ready = False
    ssl_hooked = False
    baseline_info = {}

    def on_message(message, data):
        nonlocal script_error, ready, ssl_hooked, baseline_info
        nonlocal net_response_count, discovery_blob_count

        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                ptype = payload.get("type")

                if ptype == "ssl_data" and data:
                    ssl_ptr = payload.get("ssl_ptr", "?")
                    chunk_num = payload.get("chunk_num", 0)
                    log_debug(f"  [SSL] chunk #{chunk_num}: {len(data)} bytes from {ssl_ptr}")

                    # Save raw chunk
                    chunk_file = os.path.join(OUTPUT_DIR, f"raw_chunk_{chunk_num:04d}.bin")
                    with open(chunk_file, "wb") as f:
                        f.write(data)

                    assembler.feed(ssl_ptr, data)
                    for resp in assembler.get_new_responses():
                        _handle_network_response(resp)

                elif ptype == "http_data" and data:
                    log_debug(f"  [HTTP] {len(data)} bytes")
                    _handle_raw_body(data, "http")

                elif ptype == "discovery_blob" and data:
                    key_name = payload.get("key_name", "?")
                    is_new = payload.get("is_new_key", False)
                    new_addrs = payload.get("new_addr_count", 0)
                    key_offset = payload.get("key_offset", 0)

                    discovery_blob_count += 1
                    tag = "NEW KEY" if is_new else "NEW ADDRS"
                    log(f"\n  !! [{tag}] \"{key_name}\" — "
                        f"{new_addrs} new address(es), {len(data):,} bytes")

                    # Save raw blob
                    safe_name = key_name.replace("/", "_")[:40]
                    raw_file = os.path.join(
                        OUTPUT_DIR,
                        f"disc_{discovery_blob_count:03d}_{safe_name}.bin")
                    with open(raw_file, "wb") as f:
                        f.write(data)
                    log(f"     Raw: {raw_file}")

                    # Try to decode MsgPack around the key
                    structures = find_msgpack_at_key(data, key_offset)
                    if structures:
                        best = structures[0]
                        strip_pii(best["data"])

                        json_file = raw_file.replace(".bin", ".json")
                        with open(json_file, "w", encoding="utf-8") as f:
                            json.dump(best["data"], f, indent=2,
                                      ensure_ascii=False, default=str)
                        log(f"     JSON: {json_file}")
                        summarize_decoded(best["data"], f"[{key_name}] ")

                        # Flag if it contains known skill IDs
                        skill_ids = deep_find_skill_ids(best["data"])
                        known_hits = skill_ids & KNOWN_SKILL_IDS
                        if known_hits:
                            log(f"     ★ CONTAINS {len(known_hits)} KNOWN SKILL IDs: {sorted(known_hits)}")
                        if skill_ids:
                            log(f"     Skill-range integers found: {len(skill_ids)}")

                        captured_files.append(json_file)
                    else:
                        log(f"     Could not decode MsgPack (raw saved)")
                        captured_files.append(raw_file)

                elif ptype == "baseline_keys":
                    baseline_info = payload.get("keys", {})

                elif ptype == "ready":
                    ready = True
                    ssl_hooked = payload.get("ssl_hooked", False)

                elif ptype == "tick":
                    secs = payload.get("seconds", 0)
                    net = payload.get("network_chunks", 0)
                    newk = payload.get("new_keys_found", 0)
                    log(f"  [{secs}s] net_chunks={net}, "
                        f"new_keys={newk}, files={len(captured_files)}")

            elif isinstance(payload, str):
                log(f"  [JS] {payload}")

        elif msg_type == "error":
            script_error = message
            log(f"\n  [X] JS Error: {message.get('description', 'unknown')}")
            stack = message.get("stack")
            if stack:
                for line in str(stack).splitlines():
                    log(f"      {line}")

        elif msg_type == "log":
            log(f"  [JS] {message.get('payload', '')}")

    def _handle_network_response(resp):
        nonlocal net_response_count
        body = resp.get("body", b"")
        if not body or len(body) < 10:
            return
        status = resp.get("status", "")
        headers = resp.get("headers", {})
        log_debug(f"  [NET] {status[:60]}, {len(body)} bytes, "
                  f"ct={headers.get('content-type', '?')}")
        _handle_raw_body(body, "ssl")

    def _handle_raw_body(body, source):
        nonlocal net_response_count

        # Try gzip
        if body[:2] == b'\x1f\x8b':
            try:
                body = gzip.decompress(body)
                log_debug(f"  [NET] gunzipped → {len(body)} bytes")
            except Exception:
                pass

        # Try MsgPack decode — save EVERYTHING that decodes, no filtering
        result = try_decode_msgpack(body)
        if result is None:
            return

        decoded, offset = result
        net_response_count += 1
        rid = net_response_count

        strip_pii(decoded)

        # Save
        json_file = os.path.join(OUTPUT_DIR, f"net_{rid:03d}.json")
        raw_file = os.path.join(OUTPUT_DIR, f"net_{rid:03d}.msgpack")
        with open(raw_file, "wb") as f:
            f.write(body)
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(decoded, f, indent=2, ensure_ascii=False, default=str)

        dtype = "map" if isinstance(decoded, dict) else "array"
        log(f"\n  !! NET #{rid} ({source}): {dtype}[{len(decoded)}] "
            f"({len(body):,} bytes, offset={offset})")
        log(f"     Saved: {json_file}")
        summarize_decoded(decoded, f"[NET#{rid}] ")

        # Flag skill IDs
        skill_ids = deep_find_skill_ids(decoded)
        known_hits = skill_ids & KNOWN_SKILL_IDS
        if known_hits:
            log(f"     ★ CONTAINS {len(known_hits)} KNOWN SKILL IDs: {sorted(known_hits)}")
        if skill_ids:
            log(f"     Skill-range integers (100k-999k): {len(skill_ids)} found")

        captured_files.append(json_file)

    try:
        script = session.create_script(FRIDA_SCRIPT, runtime="v8")
        script.on("message", on_message)
        log("[*] Loading discovery tool (baseline + hooks)...")
        try:
            script.load()
        except Exception as e:
            if "timeout" in str(e).lower():
                log("[*] Baseline scan still running...")
            else:
                raise
    except Exception as e:
        log(f"[X] Failed: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.exit(1)

    log("[*] Waiting for baseline...")
    for _ in range(180):
        time.sleep(0.5)
        if ready or script_error:
            break

    if not ready and not script_error:
        log("[*] Baseline still running, continuing anyway...")

    # Print baseline summary
    if baseline_info:
        log()
        log(f"  Baseline: {len(baseline_info)} key names found in memory")
        log_debug(f"  Baseline keys: {json.dumps(baseline_info, indent=2)}")
        # Save baseline for reference
        bl_file = os.path.join(OUTPUT_DIR, "baseline_keys.json")
        with open(bl_file, "w") as f:
            json.dump(baseline_info, f, indent=2)
        log(f"  Saved baseline key list: {bl_file}")

    log()
    log("=" * 60)
    if ssl_hooked:
        log("  BASELINE DONE — SSL/HTTP hooks ACTIVE")
        log("  Every API response will be saved to intercepted_responses/")
    else:
        log("  BASELINE DONE — no SSL hooks (relying on memory diff)")
    log()
    log("  Perform the in-game action now!")
    log("  Wait ~10-15s, then Ctrl+C to stop and see summary.")
    log("=" * 60)
    log()

    try:
        for _ in range(MAX_WAIT_SECONDS):
            time.sleep(1)
            if script_error:
                break
    except KeyboardInterrupt:
        log("\n[*] Stopped.")

    # ── Summary ────────────────────────────────────────────────────────
    log()
    log("=" * 60)
    log("  CAPTURE SUMMARY")
    log("=" * 60)
    log(f"  Network responses decoded:  {net_response_count}")
    log(f"  Memory discovery blobs:     {discovery_blob_count}")
    log(f"  Total files saved:          {len(captured_files)}")
    log(f"  SSL/HTTP hooks:             {'active' if ssl_hooked else 'not available'}")
    log()
    if captured_files:
        log("  Saved files:")
        for f in captured_files:
            log(f"    {f}")
    else:
        log("  No data captured.")
        log()
        log("  TROUBLESHOOTING:")
        log("  - Make sure the game is running")
        log("  - Try running as Administrator")
        log("  - Check if the action actually triggers a server call")
        log("  - Check intercept_debug.log for SSL hook diagnostics")
    log()
    log(f"  Output dir:  {OUTPUT_DIR}")
    log(f"  Debug log:   {LOG_FILE}")
    log("=" * 60)


# ── Re-analyze existing blob ──────────────────────────────────────────────

def analyze_existing_blob(filepath):
    log("=" * 60)
    log(f"  Re-analyzing: {filepath}")
    log("=" * 60)

    with open(filepath, "rb") as f:
        raw = f.read()
    log(f"  Loaded {len(raw):,} bytes")

    # Try direct MsgPack
    result = try_decode_msgpack(raw)
    if result:
        decoded, offset = result
        log(f"  Decoded MsgPack at offset {offset}")
        strip_pii(decoded)
        summarize_decoded(decoded)

        skill_ids = deep_find_skill_ids(decoded)
        known_hits = skill_ids & KNOWN_SKILL_IDS
        if known_hits:
            log(f"  ★ KNOWN SKILL IDs: {sorted(known_hits)}")
        if skill_ids:
            log(f"  All skill-range integers: {sorted(skill_ids)}")

        out_file = os.path.splitext(filepath)[0] + "_parsed.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(decoded, f, indent=2, ensure_ascii=False, default=str)
        log(f"  Saved: {out_file}")
        return

    # Try scanning for MsgPack key suffixes
    log("  Direct decode failed, scanning for key patterns...")
    for suffix in [b"_array", b"_list", b"_data", b"_info", b"skill"]:
        pos = 0
        while True:
            idx = raw.find(suffix, pos)
            if idx == -1:
                break
            log_debug(f"  Found '{suffix.decode()}' at offset {idx}")
            structures = find_msgpack_at_key(raw, idx)
            if structures:
                best = structures[0]
                strip_pii(best["data"])
                log(f"  Found: {best['description']} at offset {best['offset']}")
                summarize_decoded(best["data"])

                skill_ids = deep_find_skill_ids(best["data"])
                if skill_ids:
                    log(f"  Skill-range ints: {sorted(skill_ids)}")

                out_file = (os.path.splitext(filepath)[0] +
                            f"_at_{best['offset']}.json")
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(best["data"], f, indent=2,
                              ensure_ascii=False, default=str)
                log(f"  Saved: {out_file}")
            pos = idx + len(suffix)

    log("  Done.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--analyze":
        if len(sys.argv) < 3:
            print("Usage: python intercept_api.py --analyze <file>")
            sys.exit(1)
        analyze_existing_blob(sys.argv[2])
    else:
        main()

