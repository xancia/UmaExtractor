# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
"""
Uma Musume API Interceptor
============================
Instead of scanning memory for deserialized data, this hooks the game's
network/API response pipeline to capture raw MsgPack BEFORE it's parsed
into C# objects.

The game uses HTTP POST with MsgPack request/response bodies.
We hook at the point where the response bytes are available and
look for our target IDs in the raw MsgPack stream.

Usage:
  1. Run this script BEFORE navigating to the target page
  2. Navigate to the page in-game
  3. The script captures API responses and checks for target IDs

Output:
  - intercepted_responses/ folder with raw .msgpack + .json files
  - intercept_debug.log with full details
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
MAX_WAIT_SECONDS = 600  # 10 minutes — navigate to the page during this time

# IDs we're looking for in API responses
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

INTERCEPT_SCRIPT = r"""
console.log("=== Uma Musume API Interceptor ===");
console.log("Hooking network response handlers...");
console.log("Navigate to the target page now!");

(function() {
    let responseCount = 0;

    // ── Strategy 1: Hook il2cpp methods ──────────────────────────────
    // The game is a Unity il2cpp app. We look for common patterns in
    // the game's HTTP response handling.

    // Find the il2cpp base module
    const il2cppModule = Process.findModuleByName("GameAssembly.dll") ||
                         Process.findModuleByName("il2cpp.dll") ||
                         Process.findModuleByName("libil2cpp.so");

    if (il2cppModule) {
        console.log(`Found il2cpp module: ${il2cppModule.name} at ${il2cppModule.base} (${il2cppModule.size} bytes)`);
        send({ type: 'status', message: `Found ${il2cppModule.name}, scanning for hooks...` });
    } else {
        console.log("WARNING: Could not find il2cpp module!");
        send({ type: 'status', message: 'No il2cpp module found - trying alternative hooks' });
    }

    // ── Strategy 2: Hook UnityWebRequest completion ──────────────────
    // Scan for the MsgPack deserialize pattern in memory.
    // Uma Musume uses MsgPack for API communication.
    // We look for responses by scanning for MsgPack map/array headers
    // in data that flows through common Unity networking code paths.

    // ── Strategy 3: Monitor memory for new MsgPack blobs ─────────────
    // Periodically scan for newly appeared MsgPack data containing our IDs.
    // This catches the brief window when the response is in memory as raw bytes.

    const targetIds = """ + json.dumps(TARGET_IDS) + r""";
    const scanProtection = "rw-";
    const minRangeSize = 64 * 1024;
    const maxRangeSize = 500 * 1024 * 1024;

    // Build MsgPack uint32 patterns for our target IDs
    function hex(b) { return ('0' + b.toString(16).toUpperCase()).slice(-2); }

    const msgpackPatterns = targetIds.map(id => {
        const b3 = (id >>> 24) & 0xFF, b2 = (id >>> 16) & 0xFF;
        const b1 = (id >>> 8) & 0xFF, b0 = id & 0xFF;
        return {
            id: id,
            // MsgPack uint32 encoding: CE xx xx xx xx
            pattern: `CE ${hex(b3)} ${hex(b2)} ${hex(b1)} ${hex(b0)}`,
            size: 5
        };
    });

    console.log(`Monitoring for ${msgpackPatterns.length} MsgPack-encoded IDs...`);

    // Track known regions so we only report NEW occurrences
    const knownHits = new Set();

    function scanForMsgPackIds() {
        const ranges = Process.enumerateRanges({protection: scanProtection, coalesce: true});
        const candidates = ranges.filter(r => r.size >= minRangeSize && r.size <= maxRangeSize);

        let newHits = {};  // regionKey -> { ids: Set, addresses: [] }

        for (const pat of msgpackPatterns) {
            for (const range of candidates) {
                try {
                    const results = Memory.scanSync(range.base, range.size, pat.pattern);
                    for (const r of results) {
                        const key = r.address.toString();
                        if (knownHits.has(key)) continue;

                        const regionKey = range.base.toString();
                        if (!newHits[regionKey]) {
                            newHits[regionKey] = { ids: new Set(), addresses: [], base: range.base, size: range.size };
                        }
                        newHits[regionKey].ids.add(pat.id);
                        newHits[regionKey].addresses.push({ id: pat.id, address: r.address });
                        knownHits.add(key);
                    }
                } catch(e) { continue; }
            }
        }

        // Check if any region has multiple target IDs as MsgPack — that's an API response!
        const promising = Object.values(newHits).filter(h => h.ids.size >= 3);

        for (const region of promising) {
            console.log(`\n!!! NEW MsgPack region with ${region.ids.size}/${targetIds.length} IDs !!!`);
            console.log(`Region: ${region.base}, size=${region.size}`);

            // Find extent of hits
            let minAddr = region.addresses[0].address;
            let maxAddr = region.addresses[0].address;
            for (const a of region.addresses) {
                if (a.address.compare(minAddr) < 0) minAddr = a.address;
                if (a.address.compare(maxAddr) > 0) maxAddr = a.address;
            }

            // Read a generous chunk: from 256KB before first hit to 1MB after last
            const readBefore = 256 * 1024;
            const readAfter = 1 * 1024 * 1024;
            const readStart = minAddr.sub(readBefore);
            const clampedStart = readStart.compare(region.base) < 0 ? region.base : readStart;
            const span = maxAddr.sub(clampedStart).toInt32() + readAfter;
            const maxRead = Math.min(span, region.size - clampedStart.sub(region.base).toInt32(), 25 * 1024 * 1024);

            if (maxRead <= 0) continue;

            try {
                const data = clampedStart.readByteArray(maxRead);
                const hitOffsets = region.addresses.map(a => ({
                    id: a.id,
                    byteOffset: a.address.sub(clampedStart).toInt32()
                })).filter(h => h.byteOffset >= 0 && h.byteOffset < maxRead);

                responseCount++;
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
                console.log(`Failed to read: ${e}`);
            }
        }

        return promising.length;
    }

    // ── Strategy 4: Hook common crypto/compression functions ──────────
    // Uma Musume likely decrypts/decompresses API responses.
    // Look for common patterns.

    // Try to hook Cygames' response handler by finding MsgPack-related exports
    if (il2cppModule) {
        // Search for "Deserialize" method references in il2cpp
        const exports = il2cppModule.enumerateExports();
        const interestingExports = exports.filter(e =>
            e.name && (
                e.name.toLowerCase().includes("deserialize") ||
                e.name.toLowerCase().includes("msgpack") ||
                e.name.toLowerCase().includes("unpack") ||
                e.name.toLowerCase().includes("response") ||
                e.name.toLowerCase().includes("download")
            )
        );

        if (interestingExports.length > 0) {
            console.log(`Found ${interestingExports.length} potentially interesting exports:`);
            for (const exp of interestingExports.slice(0, 30)) {
                console.log(`  ${exp.name} at ${exp.address}`);
            }
            send({
                type: 'exports_found',
                count: interestingExports.length,
                samples: interestingExports.slice(0, 50).map(e => ({ name: e.name, address: e.address.toString() }))
            });
        } else {
            console.log("No obviously named exports found (normal for il2cpp stripped builds)");
        }

        // Also look for "lz4" or "gzip" which might be used for response compression
        const compressionExports = exports.filter(e =>
            e.name && (
                e.name.toLowerCase().includes("lz4") ||
                e.name.toLowerCase().includes("gzip") ||
                e.name.toLowerCase().includes("decompress") ||
                e.name.toLowerCase().includes("inflate")
            )
        );

        if (compressionExports.length > 0) {
            console.log(`Found ${compressionExports.length} compression-related exports:`);
            for (const exp of compressionExports.slice(0, 10)) {
                console.log(`  ${exp.name} at ${exp.address}`);
            }
        }
    }

    // ── Periodic scanning ────────────────────────────────────────────
    // Scan every 2 seconds for new MsgPack-encoded IDs appearing in memory.
    // This catches the window between API response receipt and deserialization.

    let scanCount = 0;
    const scanInterval = setInterval(() => {
        scanCount++;
        const found = scanForMsgPackIds();
        if (scanCount % 15 === 0) {
            send({ type: 'scan_tick', scan_count: scanCount, elapsed_seconds: scanCount * 2 });
        }
    }, 2000);

    // Initial scan
    console.log("\nRunning initial scan...");
    scanForMsgPackIds();
    console.log("Initial scan complete. Monitoring for new API responses...");
    console.log(">>> Navigate to the target page NOW <<<");

    send({ type: 'ready', message: 'Interceptor ready. Navigate to the target page.' });
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


def find_msgpack_in_blob(raw_bytes, known_ids):
    """
    Scan raw bytes for MsgPack structures containing target IDs.
    Only checks at MsgPack container header positions — not brute force.
    """
    known_set = set(known_ids)
    results = []
    data_len = len(raw_bytes)

    # First, find where the MsgPack uint32-encoded IDs actually are
    id_offsets = {}
    for target_id in known_ids:
        b3 = (target_id >> 24) & 0xFF
        b2 = (target_id >> 16) & 0xFF
        b1 = (target_id >> 8) & 0xFF
        b0 = target_id & 0xFF
        pattern = bytes([0xCE, b3, b2, b1, b0])
        pos = 0
        while True:
            idx = raw_bytes.find(pattern, pos)
            if idx == -1:
                break
            if target_id not in id_offsets:
                id_offsets[target_id] = []
            id_offsets[target_id].append(idx)
            pos = idx + 5

    if not id_offsets:
        return results

    # Find the earliest ID occurrence
    min_offset = min(off for offsets in id_offsets.values() for off in offsets)

    # Scan backwards from earliest ID to find the enclosing MsgPack container
    for back in range(min_offset, max(0, min_offset - 512 * 1024), -1):
        b = raw_bytes[back]
        is_container = False
        if 0x82 <= b <= 0x8F or b in (0xDE, 0xDF):
            is_container = True
        elif 0x92 <= b <= 0x9F or b in (0xDC, 0xDD):
            is_container = True

        if not is_container:
            continue

        try:
            chunk = raw_bytes[back:min(back + 25 * 1024 * 1024, data_len)]
            unpacker = msgpack.Unpacker(raw=False, max_buffer_size=50 * 1024 * 1024)
            unpacker.feed(chunk)
            decoded = unpacker.unpack()
            if decoded is None or (isinstance(decoded, (list, dict)) and len(decoded) == 0):
                continue
            consumed = unpacker.tell()
            found_ids = deep_find_ids(decoded, known_set)
            if len(found_ids) >= 2:
                if isinstance(decoded, list):
                    desc = f"array[{len(decoded)}]"
                elif isinstance(decoded, dict):
                    desc = f"map[{len(decoded)} keys]"
                else:
                    desc = type(decoded).__name__
                results.append({
                    "offset": back,
                    "description": desc,
                    "found_ids": sorted(found_ids),
                    "found_count": len(found_ids),
                    "data": decoded,
                    "consumed": consumed,
                })
                if len(found_ids) == len(known_ids):
                    break  # Perfect match
        except Exception:
            continue

    results.sort(key=lambda r: r["found_count"], reverse=True)
    return results


# ── Main ───────────────────────────────────────────────────────────────────

PII_FIELDS = ["viewer_id", "owner_viewer_id", "dmm_viewer_id"]


def main():
    log("=" * 60)
    log("  Uma Musume API Interceptor")
    log(f"  Looking for IDs: {TARGET_IDS}")
    log(f"  Debug log: {LOG_FILE}")
    log(f"  Output dir: {OUTPUT_DIR}")
    log("=" * 60)
    log()
    log("  HOW TO USE:")
    log("  1. Keep this running")
    log("  2. In the game, navigate to the page with the data you need")
    log("  3. The script will detect new MsgPack data appearing in memory")
    log("  4. Results saved to intercepted_responses/")
    log()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    blobs = []
    done = False
    script_error = None
    found_target = False
    exports_info = None

    def on_message(message, data):
        nonlocal done, script_error, found_target, exports_info

        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                ptype = payload.get("type")

                if ptype == "msgpack_blob" and data:
                    resp_id = payload.get("response_id", 0)
                    matched = payload.get("matched_id_count", 0)
                    matched_ids = payload.get("matched_ids", [])

                    log(f"\n{'!' * 60}")
                    log(f"  NEW MSGPACK BLOB #{resp_id}")
                    log(f"  {matched}/{len(TARGET_IDS)} target IDs found as MsgPack!")
                    log(f"  IDs: {matched_ids}")
                    log(f"  Size: {len(data):,} bytes")
                    log(f"{'!' * 60}")

                    # Save raw blob
                    raw_file = os.path.join(OUTPUT_DIR, f"response_{resp_id:03d}.msgpack")
                    with open(raw_file, "wb") as f:
                        f.write(data)
                    log(f"  Raw blob saved: {raw_file}")

                    # Try to find and parse MsgPack structures
                    log("  Searching for MsgPack structures...")
                    structures = find_msgpack_in_blob(data, TARGET_IDS)

                    if structures:
                        best = structures[0]
                        log(f"  FOUND: {best['description']} with {best['found_count']}/{len(TARGET_IDS)} IDs")
                        log(f"  IDs: {best['found_ids']}")

                        result_data = best["data"]

                        # Strip PII
                        if isinstance(result_data, list):
                            for item in result_data:
                                if isinstance(item, dict):
                                    for pii in PII_FIELDS:
                                        item.pop(pii, None)
                        elif isinstance(result_data, dict):
                            for pii in PII_FIELDS:
                                result_data.pop(pii, None)

                        json_file = os.path.join(OUTPUT_DIR, f"response_{resp_id:03d}.json")
                        with open(json_file, "w", encoding="utf-8") as f:
                            json.dump(result_data, f, indent=2, ensure_ascii=False, default=str)
                        log(f"  Parsed JSON saved: {json_file}")

                        # Show preview
                        if isinstance(result_data, dict):
                            keys = list(result_data.keys())[:20]
                            log(f"  Top-level keys: {keys}")
                            # Look for array keys
                            for k in keys:
                                v = result_data[k]
                                if isinstance(v, list):
                                    log(f"    {k}: array[{len(v)}]")
                                    if v and isinstance(v[0], dict):
                                        log(f"      item keys: {list(v[0].keys())[:10]}")
                        elif isinstance(result_data, list):
                            log(f"  Array with {len(result_data)} items")
                            if result_data and isinstance(result_data[0], dict):
                                log(f"  Item keys: {list(result_data[0].keys())[:10]}")

                        if best["found_count"] == len(TARGET_IDS):
                            found_target = True
                            log("\n  *** ALL TARGET IDs FOUND! ***")
                            log(f"  Full data saved to: {json_file}")

                        blobs.append((payload, data, structures))
                    else:
                        log("  Could not parse MsgPack structures from blob")
                        log("  Raw blob saved for manual inspection")
                        blobs.append((payload, data, []))

                elif ptype == "scan_tick":
                    elapsed = payload.get("elapsed_seconds", 0)
                    count = payload.get("scan_count", 0)
                    log_debug(f"Scan tick #{count} ({elapsed}s elapsed)")
                    if count % 15 == 0:
                        log(f"[*] Monitoring... {elapsed}s elapsed, {len(blobs)} blobs captured")

                elif ptype == "status":
                    log(f"[*] {payload.get('message', '')}")

                elif ptype == "ready":
                    log(f"\n[*] {payload.get('message', '')}")
                    log("[*] >>> Navigate to the target page in the game NOW <<<\n")

                elif ptype == "exports_found":
                    exports_info = payload
                    log_debug(f"Exports found: {json.dumps(payload, indent=2)}")

            elif isinstance(payload, str):
                log(f"[JS] {payload}")

        elif msg_type == "error":
            script_error = message
            log(f"\n[X] JS Error: {message.get('description', 'unknown')}")
            stack = message.get("stack")
            if stack:
                for line in str(stack).splitlines():
                    log(f"    {line}")

        elif msg_type == "log":
            log(f"[JS] {message.get('payload', '')}")

    try:
        script = session.create_script(INTERCEPT_SCRIPT, runtime="v8")
        script.on("message", on_message)
        log("[*] Loading interceptor...")
        try:
            script.load()
        except Exception as e:
            if "timeout" in str(e).lower():
                log("[*] Script load timed out, interceptor continues in background...")
            else:
                raise
    except Exception as e:
        log(f"[X] Failed to load script: {type(e).__name__}: {e}")
        traceback.print_exc()
        logger.debug(traceback.format_exc())
        sys.exit(1)

    log(f"[*] Interceptor running (up to {MAX_WAIT_SECONDS}s)...")
    log("[*] Navigate to the page with the data you need.")
    log("[*] Press Ctrl+C to stop early.\n")

    try:
        for i in range(MAX_WAIT_SECONDS):
            time.sleep(1)
            if script_error or found_target:
                break
    except KeyboardInterrupt:
        log("\n[*] Stopped by user.")

    # Summary
    log()
    log("=" * 60)
    log("  INTERCEPT SUMMARY")
    log("=" * 60)
    log(f"  Total MsgPack blobs captured: {len(blobs)}")
    if found_target:
        log("  STATUS: ALL TARGET IDs FOUND!")
    elif blobs:
        log("  STATUS: Some blobs captured, check intercepted_responses/")
    else:
        log("  STATUS: No MsgPack-encoded target IDs detected")
        log()
        log("  Possible reasons:")
        log("    - The page wasn't loaded during monitoring")
        log("    - The data uses a different encoding (not MsgPack uint32)")
        log("    - The response is compressed/encrypted before MsgPack parsing")
        log()
        log("  Try:")
        log("    - Run this script, THEN navigate to the page")
        log("    - Try navigating away and back to force a fresh API call")

    if exports_info:
        log(f"\n  il2cpp exports found: {exports_info.get('count', 0)}")
        samples = exports_info.get("samples", [])
        if samples:
            log("  Potentially hookable functions:")
            for s in samples[:10]:
                log(f"    {s['name']} @ {s['address']}")

    log(f"\n  Output: {OUTPUT_DIR}")
    log(f"  Debug log: {LOG_FILE}")
    log("=" * 60)


if __name__ == "__main__":
    main()

