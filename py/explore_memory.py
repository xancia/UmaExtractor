# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
"""
Uma Musume Memory Explorer
===========================
Frida exploration script that scans game memory for MsgPack-encoded data
structures. Uses Memory.scanSync (native speed) to find key patterns fast.

Usage:
  1. Open Uma Musume and navigate to the page you want to explore
  2. Wait for it to fully load (3-5 seconds)
  3. Run:  python explore_memory.py
  4. Check the console output + explore_results.json

Strategy:
  Instead of scanning every byte in JS (way too slow), we use Frida's
  native Memory.scanSync to search for known MsgPack suffix patterns like
  "_array", "_list", "_data", "_info" etc. Then read backwards from each
  match to recover the full key name, and forwards to peek at the value.
"""
import json
import os
import sys
import time
import traceback

import frida
import msgpack

# ── Process targeting ──────────────────────────────────────────────────────

TARGET_PROCESS_NAMES = [
    "UmamusumePrettyDerby.exe",
    "UmamusumePrettyDerby",
]
PROCESS_KEYWORDS = ["uma", "musume", "derby", "cygames"]
MAX_WAIT_SECONDS = 1200

# ── The injected Frida script ──────────────────────────────────────────────
#
# Uses Memory.scanSync (native C speed) to search for suffix patterns,
# then reads surrounding bytes to reconstruct key names and peek at values.

EXPLORE_SCRIPT = r"""
console.log("=== Uma Musume Memory Explorer ===");
console.log("Scanning memory for MsgPack data structures (fast mode)...");

(function() {
    const scanProtection = "rw-";
    const minRangeSize = 64 * 1024;         // 64 KB
    const maxRangeSize = 500 * 1024 * 1024;  // 500 MB

    // ── Suffix patterns to search for ─────────────────────────────────
    // These are ASCII byte sequences commonly found at the end of
    // MsgPack key names in game data. Memory.scanSync runs natively = fast.
    const suffixPatterns = [
        { name: "_array",  hex: "5F 61 72 72 61 79" },
        { name: "_list",   hex: "5F 6C 69 73 74" },
        { name: "_data",   hex: "5F 64 61 74 61" },
        { name: "_info",   hex: "5F 69 6E 66 6F" },
        { name: "_id",     hex: "5F 69 64" },
        { name: "_num",    hex: "5F 6E 75 6D" },
        { name: "_type",   hex: "5F 74 79 70 65" },
        { name: "_name",   hex: "5F 6E 61 6D 65" },
        { name: "_count",  hex: "5F 63 6F 75 6E 74" },
        { name: "_time",   hex: "5F 74 69 6D 65" },
        { name: "_flag",   hex: "5F 66 6C 61 67" },
        { name: "_status", hex: "5F 73 74 61 74 75 73" },
    ];

    // ── Collect memory regions ────────────────────────────────────────
    const rawRanges = Process.enumerateRanges({protection: scanProtection, coalesce: true});
    const ranges = [];
    for (const r of rawRanges) {
        if (r.size >= minRangeSize && r.size <= maxRangeSize) {
            ranges.push(r);
        }
    }
    ranges.sort((a, b) => b.size - a.size);

    console.log(`Found ${ranges.length} scannable rw- regions (from ${rawRanges.length} total)`);
    send({ type: 'status', message: `Scanning ${ranges.length} regions with ${suffixPatterns.length} patterns...` });

    // ── Helpers ───────────────────────────────────────────────────────

    // Read a MsgPack string starting at pos in a Uint8Array
    function readMsgPackStr(view, pos) {
        if (pos < 0 || pos >= view.length) return null;
        const b = view[pos];
        // fixstr: 0xA0-0xBF
        if (b >= 0xA0 && b <= 0xBF) {
            const len = b & 0x1F;
            if (pos + 1 + len > view.length) return null;
            let s = '';
            for (let i = 0; i < len; i++) s += String.fromCharCode(view[pos + 1 + i]);
            return { str: s, nextPos: pos + 1 + len };
        }
        // str8: 0xD9
        if (b === 0xD9 && pos + 2 <= view.length) {
            const len = view[pos + 1];
            if (len > 200 || pos + 2 + len > view.length) return null;
            let s = '';
            for (let i = 0; i < len; i++) s += String.fromCharCode(view[pos + 2 + i]);
            return { str: s, nextPos: pos + 2 + len };
        }
        // str16: 0xDA
        if (b === 0xDA && pos + 3 <= view.length) {
            const len = (view[pos + 1] << 8) | view[pos + 2];
            if (len > 500 || pos + 3 + len > view.length) return null;
            let s = '';
            for (let i = 0; i < len; i++) s += String.fromCharCode(view[pos + 3 + i]);
            return { str: s, nextPos: pos + 3 + len };
        }
        return null;
    }

    // Read array header at pos
    function readArrayHeader(view, pos) {
        if (pos >= view.length) return null;
        const b = view[pos];
        if (b >= 0x90 && b <= 0x9F) return { len: b - 0x90, nextPos: pos + 1 };
        if (b === 0xDC && pos + 3 <= view.length) return { len: (view[pos+1] << 8) | view[pos+2], nextPos: pos + 3 };
        if (b === 0xDD && pos + 5 <= view.length) return { len: (((view[pos+1] << 24)>>>0) + (view[pos+2] << 16) + (view[pos+3] << 8) + view[pos+4]) >>> 0, nextPos: pos + 5 };
        return null;
    }

    // Read map header at pos
    function readMapHeader(view, pos) {
        if (pos >= view.length) return null;
        const b = view[pos];
        if (b >= 0x80 && b <= 0x8F) return { len: b - 0x80, nextPos: pos + 1 };
        if (b === 0xDE && pos + 3 <= view.length) return { len: (view[pos+1] << 8) | view[pos+2], nextPos: pos + 3 };
        if (b === 0xDF && pos + 5 <= view.length) return { len: (((view[pos+1] << 24)>>>0) + (view[pos+2] << 16) + (view[pos+3] << 8) + view[pos+4]) >>> 0, nextPos: pos + 5 };
        return null;
    }

    // Check if a string looks like a valid MsgPack key name
    function isValidKey(s) {
        if (s.length < 2 || s.length > 80) return false;
        for (let i = 0; i < s.length; i++) {
            const c = s.charCodeAt(i);
            if (c < 0x20 || c > 0x7E) return false;
        }
        return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(s);
    }

    // Try to find the MsgPack string key that contains the match position.
    // We read a small window around the match and look backwards for
    // a fixstr/str8 marker whose string spans the match address.
    function findKeyAtMatch(regionBase, matchAddr, regionSize) {
        // Read 200 bytes before and 600 bytes after the match
        const beforeBytes = 200;
        const afterBytes = 600;
        const windowStart = matchAddr.sub(beforeBytes);
        // Don't go before the region
        const clampedStart = windowStart.compare(regionBase) < 0 ? regionBase : windowStart;
        const offset = matchAddr.sub(clampedStart).toInt32();
        const totalRead = Math.min(offset + afterBytes, regionSize - clampedStart.sub(regionBase).toInt32());
        if (totalRead <= 0) return null;

        let view;
        try {
            view = new Uint8Array(clampedStart.readByteArray(totalRead));
        } catch(e) {
            return null;
        }

        // The suffix match is at position `offset` in our window.
        // Scan backwards from offset to find a fixstr/str8 marker whose
        // string would include the matched bytes.
        for (let back = 0; back < Math.min(offset, 100); back++) {
            const tryPos = offset - back;
            // Check for fixstr marker
            const b = view[tryPos];
            if (b >= 0xA0 && b <= 0xBF) {
                const strLen = b & 0x1F;
                // The string runs from tryPos+1 to tryPos+1+strLen
                // The suffix match should fall within that range
                if (tryPos + 1 + strLen > offset) {
                    const result = readMsgPackStr(view, tryPos);
                    if (result && isValidKey(result.str)) {
                        // Found a valid key! Now peek at what follows (the value)
                        return analyzeKeyValue(view, tryPos, result);
                    }
                }
            }
            // Check for str8 marker
            if (b === 0xD9 && tryPos + 1 < view.length) {
                const strLen = view[tryPos + 1];
                if (tryPos + 2 + strLen > offset) {
                    const result = readMsgPackStr(view, tryPos);
                    if (result && isValidKey(result.str)) {
                        return analyzeKeyValue(view, tryPos, result);
                    }
                }
            }
        }
        return null;
    }

    // Analyze the value that follows a key
    function analyzeKeyValue(view, keyPos, strResult) {
        const valuePos = strResult.nextPos;
        if (valuePos >= view.length) {
            return { key: strResult.str, valueType: 'unknown', keyPos: keyPos };
        }

        const info = { key: strResult.str, keyPos: keyPos };

        // Check for array
        const arr = readArrayHeader(view, valuePos);
        if (arr && arr.len >= 0 && arr.len < 1000000) {
            info.valueType = 'array';
            info.arrayLen = arr.len;
            // Try to read sub-keys from first element if it's a map
            info.subKeys = [];
            if (arr.len > 0) {
                const mapH = readMapHeader(view, arr.nextPos);
                if (mapH && mapH.len > 0 && mapH.len < 500) {
                    let subPos = mapH.nextPos;
                    for (let k = 0; k < Math.min(mapH.len, 30); k++) {
                        const subStr = readMsgPackStr(view, subPos);
                        if (!subStr) break;
                        if (isValidKey(subStr.str)) {
                            info.subKeys.push(subStr.str);
                        }
                        // Skip value: scan forward for next string-like byte
                        let nextPos = subStr.nextPos;
                        let advanced = false;
                        for (let skip = nextPos; skip < Math.min(nextPos + 300, view.length); skip++) {
                            const test = readMsgPackStr(view, skip);
                            if (test && isValidKey(test.str)) {
                                nextPos = skip;
                                advanced = true;
                                break;
                            }
                        }
                        if (!advanced) break;
                        subPos = nextPos;
                    }
                }
            }
            return info;
        }

        // Check for map
        const map = readMapHeader(view, valuePos);
        if (map && map.len >= 0 && map.len < 10000) {
            info.valueType = 'map';
            info.mapLen = map.len;
            return info;
        }

        // Scalar or other
        info.valueType = 'scalar';
        return info;
    }

    // ── Main scan loop ────────────────────────────────────────────────
    // For each suffix pattern, scan all regions using Memory.scanSync (native speed!)
    // Then reconstruct the full key name from each match.

    const allFindings = {};   // keyName -> best info
    let totalMatches = 0;
    let totalScans = 0;
    const totalWork = ranges.length * suffixPatterns.length;

    for (let pi = 0; pi < suffixPatterns.length; pi++) {
        const sp = suffixPatterns[pi];

        for (let ri = 0; ri < ranges.length; ri++) {
            const range = ranges[ri];
            totalScans++;

            if (totalScans % 200 === 0 || totalScans === 1) {
                const pct = Math.round(totalScans / totalWork * 100);
                send({ type: 'progress', scanned: totalScans, total: totalWork, pct: pct });
            }

            try {
                const results = Memory.scanSync(range.base, range.size, sp.hex);
                for (const match of results) {
                    totalMatches++;
                    const finding = findKeyAtMatch(range.base, match.address, range.size);
                    if (finding && finding.key) {
                        const existing = allFindings[finding.key];
                        // Keep the version with the most info (array > map > scalar)
                        if (!existing ||
                            (finding.valueType === 'array' && existing.valueType !== 'array') ||
                            (finding.subKeys && finding.subKeys.length > (existing.subKeys || []).length)) {
                            allFindings[finding.key] = finding;
                        }
                    }
                }
            } catch(e) {
                // Skip unreadable regions
                continue;
            }
        }
    }

    // ── Build results ─────────────────────────────────────────────────
    const allKeys = Object.values(allFindings).sort((a, b) => {
        // Arrays first, then maps, then scalars
        const typeOrder = { array: 0, map: 1, scalar: 2, unknown: 3 };
        const ta = typeOrder[a.valueType] ?? 3;
        const tb = typeOrder[b.valueType] ?? 3;
        if (ta !== tb) return ta - tb;
        // Larger arrays first
        if (a.arrayLen && b.arrayLen) return b.arrayLen - a.arrayLen;
        return a.key.localeCompare(b.key);
    });

    const arrayKeys = allKeys.filter(k => k.valueType === 'array');
    const mapKeys = allKeys.filter(k => k.valueType === 'map');

    console.log(`\n========================================`);
    console.log(`DONE: ${totalMatches} pattern matches -> ${allKeys.length} unique keys`);
    console.log(`  ${arrayKeys.length} array keys, ${mapKeys.length} map keys`);
    console.log(`========================================\n`);

    if (arrayKeys.length > 0) {
        console.log(`--- ARRAY KEYS (extractable data) ---`);
        for (const k of arrayKeys) {
            console.log(`  "${k.key}" -> array[${k.arrayLen}]`);
            if (k.subKeys && k.subKeys.length > 0) {
                console.log(`    sub-keys: ${k.subKeys.join(', ')}`);
            }
        }
    }

    if (mapKeys.length > 0) {
        console.log(`\n--- MAP KEYS ---`);
        for (const k of mapKeys.slice(0, 30)) {
            console.log(`  "${k.key}" -> map[${k.mapLen}]`);
        }
    }

    const scalarKeys = allKeys.filter(k => k.valueType === 'scalar' || k.valueType === 'unknown');
    if (scalarKeys.length > 0) {
        console.log(`\n--- SCALAR KEYS (${scalarKeys.length} total, showing first 40) ---`);
        for (const k of scalarKeys.slice(0, 40)) {
            console.log(`  "${k.key}"`);
        }
    }

    // Send full results to Python
    send({
        type: 'results',
        total_matches: totalMatches,
        total_keys: allKeys.length,
        array_keys: arrayKeys.map(k => ({ name: k.key, arrayLen: k.arrayLen, subKeys: k.subKeys || [] })),
        map_keys: mapKeys.map(k => ({ name: k.key, mapLen: k.mapLen })),
        scalar_keys: scalarKeys.map(k => k.key),
        all_keys: allKeys.map(k => ({ name: k.key, valueType: k.valueType, arrayLen: k.arrayLen, mapLen: k.mapLen, subKeys: k.subKeys }))
    });

    console.log("\nExploration complete!");
})();
"""


# ── Process attachment (reused from extract_umas.py) ───────────────────────

def find_candidate_processes():
    try:
        device = frida.get_local_device()
        processes = device.enumerate_processes()
    except Exception as e:
        print(f"[!] Could not enumerate processes: {e}")
        return []

    candidates = []
    for proc in processes:
        name = (proc.name or "").lower()
        if any(keyword in name for keyword in PROCESS_KEYWORDS):
            candidates.append(proc)

    candidates.sort(key=lambda p: (p.name or "").lower())
    return candidates


def attach_to_game():
    attach_errors = []

    for process_name in TARGET_PROCESS_NAMES:
        try:
            session = frida.attach(process_name)
            print(f"[OK] Attached using process name: {process_name}")
            return session
        except Exception as e:
            attach_errors.append((process_name, e))

    candidates = find_candidate_processes()
    if candidates:
        print("[!] Default name failed. Found similar processes:")
        for proc in candidates[:10]:
            print(f"    - {proc.name} (pid {proc.pid})")
        for proc in candidates:
            try:
                session = frida.attach(proc.pid)
                print(f"[OK] Attached to: {proc.name} (pid {proc.pid})")
                return session
            except Exception as e:
                attach_errors.append((f"{proc.name} (pid {proc.pid})", e))

    print("[X] Could not attach to game process.")
    for target, err in attach_errors:
        print(f"    - {target}: {type(err).__name__}: {err}")
    print("\nMake sure:")
    print("  1. Uma Musume is running")
    print("  2. You're on the page you want to explore")
    print("  3. Both game and this script run at the same privilege level")
    return None


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Uma Musume Memory Explorer (fast mode)")
    print("  Navigate to the page you want to explore, then run this.")
    print("=" * 60)
    print()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    results_data = None
    scan_done = False
    script_error = None

    def on_message(message, data):
        nonlocal results_data, scan_done, script_error

        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                ptype = payload.get("type")

                if ptype == "status":
                    print(f"[*] {payload.get('message', '')}")

                elif ptype == "progress":
                    pct = payload.get("pct", 0)
                    scanned = payload.get("scanned", 0)
                    total = payload.get("total", 0)
                    print(f"[*] Scanning... {pct}% ({scanned}/{total})", end="\r")

                elif ptype == "results":
                    results_data = payload
                    scan_done = True
                    print()  # newline after \r

                else:
                    print(f"[JS] {payload}")

            elif isinstance(payload, str):
                print(f"[JS] {payload}")

        elif msg_type == "error":
            script_error = message
            print(f"\n[X] JS Error: {message.get('description', 'unknown')}")
            stack = message.get("stack")
            if stack:
                for line in str(stack).splitlines():
                    print(f"    {line}")

        elif msg_type == "log":
            print(f"[JS] {message.get('payload', '')}")

    try:
        script = session.create_script(EXPLORE_SCRIPT, runtime="v8")
        script.on("message", on_message)
        print("[*] Loading explorer script...")
        try:
            script.load()
        except Exception as e:
            if "timeout" in str(e).lower():
                print("[*] Script load timed out, but scan is still running in the background...")
                print("    This is normal for large memory spaces. Waiting for results...")
            else:
                raise
    except Exception as e:
        print(f"[X] Failed to load script: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.exit(1)

    print(f"[*] Exploring memory (up to {MAX_WAIT_SECONDS}s)...")
    for i in range(MAX_WAIT_SECONDS):
        time.sleep(1)
        if scan_done or script_error:
            break
        if (i + 1) % 30 == 0:
            print(f"\n[*] Still running... {i + 1}s elapsed")

    if script_error and not results_data:
        print("[X] Explorer failed with a script error. See above.")
        sys.exit(1)

    if not results_data:
        print("\n[X] Explorer timed out without producing results.")
        print("    Try closing other apps and running again.")
        sys.exit(1)

    # ── Print summary ──────────────────────────────────────────────────
    array_keys = results_data.get("array_keys", [])
    map_keys = results_data.get("map_keys", [])
    scalar_keys = results_data.get("scalar_keys", [])

    print()
    print("=" * 60)
    print(f"  RESULTS: {results_data.get('total_keys', 0)} unique keys found")
    print(f"  {len(array_keys)} array keys | {len(map_keys)} map keys | {len(scalar_keys)} scalar keys")
    print("=" * 60)
    print()

    if array_keys:
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  ARRAY KEYS — These are what you can extract!          ║")
        print("╚══════════════════════════════════════════════════════════╝")
        for key in array_keys:
            name = key["name"]
            arr_len = key.get("arrayLen", "?")
            sub = key.get("subKeys", [])
            print(f'\n  📦 "{name}"  (array of {arr_len} items)')
            if sub:
                print(f"     Sub-keys: {', '.join(sub)}")

            # Print the hex pattern they'd need for an extractor
            try:
                key_bytes = name.encode("ascii")
                key_len = len(key_bytes)
                if key_len <= 31:
                    marker = 0xA0 + key_len
                    hex_pattern = f"{marker:02X} " + " ".join(f"{b:02X}" for b in key_bytes)
                    offset = 1 + key_len
                elif key_len <= 255:
                    hex_pattern = f"D9 {key_len:02X} " + " ".join(f"{b:02X}" for b in key_bytes)
                    offset = 2 + key_len
                else:
                    hex_pattern = f"DA {(key_len >> 8) & 0xFF:02X} {key_len & 0xFF:02X} " + " ".join(f"{b:02X}" for b in key_bytes)
                    offset = 3 + key_len

                print(f"     Pattern:  {hex_pattern}")
                print(f"     Offset:   +{offset} bytes to reach array value")
            except Exception:
                pass
        print()

    # ── Save to JSON ───────────────────────────────────────────────────
    output_file = os.path.abspath("explore_results.json")
    try:
        output = {
            "summary": {
                "total_matches": results_data.get("total_matches", 0),
                "total_keys": results_data.get("total_keys", 0),
                "array_key_count": len(array_keys),
                "map_key_count": len(map_keys),
                "scalar_key_count": len(scalar_keys),
            },
            "array_keys": array_keys,
            "map_keys": map_keys,
            "scalar_keys": scalar_keys,
            "all_keys": results_data.get("all_keys", []),
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"[OK] Full results saved to: {output_file}")
    except Exception as e:
        print(f"[!] Could not save results: {e}")
        print(json.dumps(results_data, indent=2))

    print()
    print("Next steps:")
    print('  1. Look at the array keys above — find the one for your target data')
    print('  2. Copy the "Pattern" hex string into your extractor script')
    print('  3. Use the "Offset" value for the arrayStart calculation')
    print('  4. Pick a sub-key for validation (like "card_id" in the veteran extractor)')


if __name__ == "__main__":
    main()

