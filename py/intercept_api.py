# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
"""
Uma Musume API Interceptor v2
===============================
Monitors game memory for MsgPack-encoded API responses containing target IDs.

Usage:
  Live capture:   python intercept_api.py
  Re-analyze:     python intercept_api.py --analyze <file.msgpack>
"""
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

TARGET_IDS = [200154, 200152, 200441, 200652, 200722, 201152]

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

def build_intercept_script(target_ids):
    ids_json = json.dumps(target_ids)
    return r"""
(function() {
    const targetIds = """ + ids_json + r""";
    const scanProtection = "rw-";
    const minRangeSize = 64 * 1024;
    const maxRangeSize = 500 * 1024 * 1024;

    function hex(b) { return ('0' + b.toString(16).toUpperCase()).slice(-2); }

    // Build BOTH uint32 (CE) and int32 (D2) MsgPack patterns for each ID
    const msgpackPatterns = [];
    for (const id of targetIds) {
        const b3 = (id >>> 24) & 0xFF, b2 = (id >>> 16) & 0xFF;
        const b1 = (id >>> 8) & 0xFF, b0 = id & 0xFF;
        // MsgPack uint32: CE xx xx xx xx
        msgpackPatterns.push({
            id: id,
            pattern: `CE ${hex(b3)} ${hex(b2)} ${hex(b1)} ${hex(b0)}`,
            label: 'uint32'
        });
        // MsgPack int32: D2 xx xx xx xx (some encoders use signed for positive values)
        msgpackPatterns.push({
            id: id,
            pattern: `D2 ${hex(b3)} ${hex(b2)} ${hex(b1)} ${hex(b0)}`,
            label: 'int32'
        });
    }

    // Track known hit addresses so we only report NEW ones
    const knownHits = new Set();
    let responseCount = 0;
    let scanCount = 0;

    function scanForMsgPackIds() {
        const ranges = Process.enumerateRanges({protection: scanProtection, coalesce: true})
            .filter(r => r.size >= minRangeSize && r.size <= maxRangeSize);

        const newHits = {};  // regionKey -> { ids, addresses, base, size }

        for (const pat of msgpackPatterns) {
            for (const range of ranges) {
                try {
                    const results = Memory.scanSync(range.base, range.size, pat.pattern);
                    for (const r of results) {
                        const key = r.address.toString();
                        if (knownHits.has(key)) continue;

                        const regionKey = range.base.toString();
                        if (!newHits[regionKey]) {
                            newHits[regionKey] = {
                                ids: new Set(), addresses: [], base: range.base, size: range.size
                            };
                        }
                        newHits[regionKey].ids.add(pat.id);
                        newHits[regionKey].addresses.push({
                            id: pat.id, address: r.address, label: pat.label
                        });
                        knownHits.add(key);
                    }
                } catch(e) { /* skip unreadable regions */ }
            }
        }

        // Report any region with 2+ target IDs appearing as NEW MsgPack data
        const promising = Object.values(newHits).filter(h => h.ids.size >= 2);

        for (const region of promising) {
            let minAddr = region.addresses[0].address;
            let maxAddr = region.addresses[0].address;
            for (const a of region.addresses) {
                if (a.address.compare(minAddr) < 0) minAddr = a.address;
                if (a.address.compare(maxAddr) > 0) maxAddr = a.address;
            }

            // Read generously: 1MB before first hit, 1MB after last hit
            const readBefore = 1 * 1024 * 1024;
            const readAfter = 1 * 1024 * 1024;
            const readStart = minAddr.sub(readBefore);
            const clampedStart = readStart.compare(region.base) < 0
                ? region.base : readStart;
            const span = maxAddr.sub(clampedStart).toInt32() + readAfter;
            const maxRead = Math.min(
                span,
                region.size - clampedStart.sub(region.base).toInt32(),
                25 * 1024 * 1024
            );
            if (maxRead <= 0) continue;

            try {
                const data = clampedStart.readByteArray(maxRead);
                const hitOffsets = region.addresses.map(a => ({
                    id: a.id, label: a.label,
                    byteOffset: a.address.sub(clampedStart).toInt32()
                })).filter(h => h.byteOffset >= 0 && h.byteOffset < maxRead);

                responseCount++;
                console.log(`Captured blob #${responseCount}: ${region.ids.size}/${targetIds.length} IDs, ${maxRead} bytes`);

                send({
                    type: 'msgpack_blob',
                    response_id: responseCount,
                    matched_id_count: region.ids.size,
                    matched_ids: Array.from(region.ids),
                    total_hits: region.addresses.length,
                    read_size: maxRead,
                    hit_offsets: hitOffsets
                }, data);
            } catch(e) {
                console.log(`Failed to read region: ${e}`);
            }
        }

        return promising.length;
    }

    // ── Initial baseline scan ────────────────────────────────────────
    console.log("Running baseline scan...");
    scanForMsgPackIds();
    console.log("Baseline complete. Monitoring for new data...");

    send({ type: 'ready' });

    // ── Poll every 1 second ──────────────────────────────────────────
    setInterval(() => {
        scanCount++;
        scanForMsgPackIds();
        if (scanCount % 30 === 0) {
            send({ type: 'tick', seconds: scanCount });
        }
    }, 1000);
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


# ── MsgPack analysis ──────────────────────────────────────────────────────

def deep_find_ids(obj, known_set, found=None, depth=0):
    if found is None:
        found = set()
    if depth > 30:
        return found
    if isinstance(obj, int) and obj in known_set:
        found.add(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, int) and k in known_set:
                found.add(k)
            deep_find_ids(v, known_set, found, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            deep_find_ids(item, known_set, found, depth + 1)
    return found


def try_unpack_at(raw_bytes, offset, known_set):
    if offset < 0 or offset >= len(raw_bytes):
        return None
    try:
        chunk = raw_bytes[offset:min(offset + 25 * 1024 * 1024, len(raw_bytes))]
        unpacker = msgpack.Unpacker(raw=False, max_buffer_size=50 * 1024 * 1024)
        unpacker.feed(chunk)
        decoded = unpacker.unpack()
        if decoded is None:
            return None
        if isinstance(decoded, (list, dict)) and len(decoded) == 0:
            return None
        consumed = unpacker.tell()
        found_ids = deep_find_ids(decoded, known_set)
        if not found_ids:
            return None
        if isinstance(decoded, list):
            desc = f"array[{len(decoded)}]"
        elif isinstance(decoded, dict):
            desc = f"map[{len(decoded)} keys]"
        else:
            desc = type(decoded).__name__
        return {
            "offset": offset,
            "description": desc,
            "found_ids": sorted(found_ids),
            "found_count": len(found_ids),
            "data": decoded,
            "consumed": consumed,
        }
    except Exception:
        return None


def find_msgpack_in_blob(raw_bytes, known_ids):
    """Try multiple strategies to find MsgPack structures containing target IDs."""
    known_set = set(known_ids)
    results = []
    data_len = len(raw_bytes)

    log_debug(f"  Parsing blob: {data_len:,} bytes")

    # Locate MsgPack-encoded IDs in the blob (CE and D2 prefixes)
    id_offsets = {}
    for target_id in known_ids:
        b3 = (target_id >> 24) & 0xFF
        b2 = (target_id >> 16) & 0xFF
        b1 = (target_id >> 8) & 0xFF
        b0 = target_id & 0xFF
        for prefix in [0xCE, 0xD2]:
            pattern = bytes([prefix, b3, b2, b1, b0])
            pos = 0
            while True:
                idx = raw_bytes.find(pattern, pos)
                if idx == -1:
                    break
                id_offsets.setdefault(target_id, []).append(idx)
                pos = idx + 5

    if not id_offsets:
        log_debug("  No MsgPack-encoded IDs found in blob")
        return results

    for tid, offsets in id_offsets.items():
        log_debug(f"  ID {tid} at byte offsets: {offsets}")

    all_offsets = [o for ol in id_offsets.values() for o in ol]
    min_offset = min(all_offsets)
    max_offset = max(all_offsets)
    log_debug(f"  ID range: {min_offset} - {max_offset}")

    # Strategy A: try from very start of blob
    log_debug("  Strategy A: start of blob...")
    for start in range(min(64, data_len)):
        r = try_unpack_at(raw_bytes, start, known_set)
        if r and r["found_count"] >= 2:
            log(f"  [A] {r['description']} @ offset {start}: "
                f"{r['found_count']}/{len(known_ids)} IDs")
            results.append(r)
            if r["found_count"] == len(known_ids):
                return results

    # Strategy B: brute-force first 8KB for container headers
    log_debug("  Strategy B: first 8KB...")
    for pos in range(min(8192, data_len)):
        b = raw_bytes[pos]
        if not (0x82 <= b <= 0x8F or b in (0xDE, 0xDF)
                or 0x92 <= b <= 0x9F or b in (0xDC, 0xDD)):
            continue
        r = try_unpack_at(raw_bytes, pos, known_set)
        if r and r["found_count"] >= 2:
            log(f"  [B] {r['description']} @ offset {pos}: "
                f"{r['found_count']}/{len(known_ids)} IDs")
            results.append(r)
            if r["found_count"] == len(known_ids):
                return results

    # Strategy C: backward from earliest ID, up to 2MB
    log_debug(f"  Strategy C: backward from {min_offset}...")
    limit = max(0, min_offset - 2 * 1024 * 1024)
    for back in range(min_offset, limit, -1):
        b = raw_bytes[back]
        if not (0x82 <= b <= 0x8F or b in (0xDE, 0xDF)
                or 0x92 <= b <= 0x9F or b in (0xDC, 0xDD)):
            continue
        r = try_unpack_at(raw_bytes, back, known_set)
        if r and r["found_count"] >= 2:
            log(f"  [C] {r['description']} @ offset {back}: "
                f"{r['found_count']}/{len(known_ids)} IDs")
            results.append(r)
            if r["found_count"] == len(known_ids):
                break

    # Strategy D: probe near each ID offset
    log_debug("  Strategy D: near each ID...")
    for offsets in id_offsets.values():
        for off in offsets:
            for probe in [0, -1, -2, -3, -4, -5, -6, -7, -8, -16, -32, -64]:
                pos = off + probe
                r = try_unpack_at(raw_bytes, pos, known_set)
                if r and r["found_count"] >= 2:
                    log_debug(f"  [D] {r['description']} @ {pos}: {r['found_count']} IDs")
                    results.append(r)

    # Deduplicate
    unique = {}
    for r in results:
        key = r["offset"]
        if key not in unique or r["found_count"] > unique[key]["found_count"]:
            unique[key] = r
    return sorted(unique.values(), key=lambda r: r["found_count"], reverse=True)


# ── Main ───────────────────────────────────────────────────────────────────

PII_FIELDS = ["viewer_id", "owner_viewer_id", "dmm_viewer_id"]


def main():
    log("=" * 60)
    log("  Uma Musume API Interceptor v2")
    log(f"  Target IDs: {TARGET_IDS}")
    log("=" * 60)
    log()
    log("  INSTRUCTIONS:")
    log("  1. Be on the CAREER END screen (before tapping acquire skills)")
    log("  2. Press Enter here to start the baseline scan")
    log("  3. Wait for 'BASELINE DONE' message")
    log("  4. THEN tap the 'acquire skills' button in-game")
    log("  5. Wait ~10 seconds, then Ctrl+C to stop")
    log()

    input("  >>> Press Enter when you are on the career end screen... ")
    log()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    blobs = []
    script_error = None
    found_target = False
    ready = False

    def on_message(message, data):
        nonlocal script_error, found_target, ready

        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                ptype = payload.get("type")

                if ptype == "msgpack_blob" and data:
                    resp_id = payload.get("response_id", 0)
                    matched = payload.get("matched_id_count", 0)
                    matched_ids = payload.get("matched_ids", [])

                    log(f"\n  !! BLOB #{resp_id}: {matched}/{len(TARGET_IDS)} IDs "
                        f"({len(data):,} bytes) — {matched_ids}")

                    raw_file = os.path.join(OUTPUT_DIR, f"response_{resp_id:03d}.msgpack")
                    with open(raw_file, "wb") as f:
                        f.write(data)
                    log(f"     Saved raw: {raw_file}")

                    structures = find_msgpack_in_blob(data, TARGET_IDS)
                    if structures:
                        best = structures[0]
                        log(f"     Parsed: {best['description']} with "
                            f"{best['found_count']}/{len(TARGET_IDS)} IDs")

                        result_data = best["data"]
                        _strip_pii(result_data)

                        json_file = os.path.join(OUTPUT_DIR, f"response_{resp_id:03d}.json")
                        with open(json_file, "w", encoding="utf-8") as f:
                            json.dump(result_data, f, indent=2, ensure_ascii=False, default=str)
                        log(f"     Saved JSON: {json_file}")
                        _preview_data(result_data)

                        if best["found_count"] == len(TARGET_IDS):
                            found_target = True
                            log("\n  *** ALL TARGET IDs FOUND! ***")

                        blobs.append((payload, data, structures))
                    else:
                        log("     Could not parse MsgPack (raw blob saved)")
                        blobs.append((payload, data, []))

                elif ptype == "ready":
                    ready = True

                elif ptype == "tick":
                    secs = payload.get("seconds", 0)
                    log(f"  [{secs}s] monitoring... {len(blobs)} blobs so far")

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

    intercept_js = build_intercept_script(TARGET_IDS)
    log_debug(f"JS script: {len(intercept_js)} chars")

    try:
        script = session.create_script(intercept_js, runtime="v8")
        script.on("message", on_message)
        log("[*] Loading interceptor (baseline scan)...")
        try:
            script.load()
        except Exception as e:
            if "timeout" in str(e).lower():
                log("[*] Baseline scan still running in background...")
            else:
                raise
    except Exception as e:
        log(f"[X] Failed: {type(e).__name__}: {e}")
        traceback.print_exc()
        logger.debug(traceback.format_exc())
        sys.exit(1)

    # Wait for baseline scan to finish
    log("[*] Waiting for baseline scan to complete...")
    for _ in range(120):
        time.sleep(0.5)
        if ready or script_error:
            break

    if not ready and not script_error:
        log("[*] Baseline still running, but continuing anyway...")

    log()
    log("=" * 60)
    log("  BASELINE DONE — tap 'acquire skills' in-game now!")
    log("  Wait ~10s after the skills page loads, then Ctrl+C.")
    log("=" * 60)
    log()

    try:
        for i in range(MAX_WAIT_SECONDS):
            time.sleep(1)
            if script_error or found_target:
                break
    except KeyboardInterrupt:
        log("\n[*] Stopped.")

    # Summary
    log()
    log("=" * 60)
    log("  SUMMARY")
    log("=" * 60)
    log(f"  Blobs captured: {len(blobs)}")
    if found_target:
        log("  STATUS: ALL TARGET IDs FOUND!")
    elif blobs:
        log("  STATUS: Partial matches — check intercepted_responses/")
    else:
        log("  STATUS: No MsgPack blobs detected")
        log("  The data might be compressed before MsgPack encoding,")
        log("  or the API response might not contain these IDs as MsgPack.")
    log(f"\n  Debug log: {LOG_FILE}")
    log("=" * 60)


def _strip_pii(data):
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


def _preview_data(data):
    if isinstance(data, dict):
        keys = list(data.keys())[:20]
        log(f"     Keys: {keys}")
        for k in keys[:5]:
            v = data[k]
            if isinstance(v, list):
                log(f"       {k}: array[{len(v)}]")
                if v and isinstance(v[0], dict):
                    log(f"         item keys: {list(v[0].keys())[:10]}")
            elif isinstance(v, dict):
                log(f"       {k}: map[{len(v)} keys]")
    elif isinstance(data, list):
        log(f"     Array with {len(data)} items")
        if data and isinstance(data[0], dict):
            log(f"     Item keys: {list(data[0].keys())[:10]}")


def analyze_existing_blob(filepath):
    """Re-analyze a previously captured .msgpack blob."""
    log("=" * 60)
    log(f"  Re-analyzing: {filepath}")
    log(f"  Target IDs: {TARGET_IDS}")
    log("=" * 60)

    with open(filepath, "rb") as f:
        raw = f.read()
    log(f"  Loaded {len(raw):,} bytes")

    structures = find_msgpack_in_blob(raw, TARGET_IDS)

    if not structures:
        log("\n  No MsgPack structures found containing target IDs.")
        return

    for i, s in enumerate(structures[:5]):
        log(f"\n  Result {i}: {s['description']} @ offset {s['offset']}")
        log(f"  {s['found_count']}/{len(TARGET_IDS)} IDs: {s['found_ids']}")

        data = s["data"]
        _strip_pii(data)
        _preview_data(data)

        out_file = os.path.splitext(filepath)[0] + f"_parsed_{i}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        log(f"  Saved: {out_file}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--analyze":
        if len(sys.argv) < 3:
            print("Usage: python intercept_api.py --analyze <file.msgpack>")
            sys.exit(1)
        analyze_existing_blob(sys.argv[2])
    else:
        main()

