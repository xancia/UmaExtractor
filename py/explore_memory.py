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
structures and logs all key names it finds. Use this to discover what data
the game holds in memory on whatever page you're currently viewing.

Usage:
  1. Open Umamusume and navigate to the page you want to explore
  2. Wait for it to fully load (3-5 seconds)
  3. Run:  python explore_memory.py
  4. Check the console output + explore_results.json

The script will:
  - Attach to the game process
  - Scan rw- memory regions for MsgPack map/array structures
  - Log all MsgPack string keys it finds
  - For each key that points to an array, log the array length and
    a sample of sub-keys from the first element
  - Dump everything to explore_results.json for offline analysis
"""
import json
import os
import sys
import time
import traceback

import frida
import msgpack

# ── Process targeting (same as extract_umas.py) ────────────────────────────

TARGET_PROCESS_NAMES = [
    "UmamusumePrettyDerby.exe",
    "UmamusumePrettyDerby",
]
PROCESS_KEYWORDS = ["uma", "musume", "derby", "cygames"]
MAX_WAIT_SECONDS = 180

# ── The injected Frida script ──────────────────────────────────────────────
#
# Strategy:
#   MsgPack maps start with 0x80-0x8F (fixmap), 0xDE (map16), 0xDF (map32).
#   Inside maps, keys are typically fixstr (0xA0-0xBF) or str8 (0xD9).
#   We scan for ALL fixstr/str8 keys in large rw- regions and collect them.
#   When a key's value is an array, we note the array length and peek at
#   sub-keys inside the first element.
#
#   This gives us a full inventory of what data structures live in memory.

EXPLORE_SCRIPT = r"""
console.log("=== Uma Musume Memory Explorer ===");
console.log("Scanning memory for MsgPack data structures...");

(function() {
    const scanProtection = "rw-";
    const minRangeSize = 64 * 1024;        // 64 KB minimum
    const maxRangeSize = 500 * 1024 * 1024; // 500 MB maximum
    const maxBytesToScan = 5 * 1024 * 1024; // scan first 5 MB of each region for keys
    
    // ── Collect memory regions ────────────────────────────────────────
    const rawRanges = Process.enumerateRanges({protection: scanProtection, coalesce: true});
    const ranges = [];
    for (const r of rawRanges) {
        if (r.size >= minRangeSize && r.size <= maxRangeSize) {
            ranges.push(r);
        }
    }
    ranges.sort((a, b) => b.size - a.size);
    
    console.log(`Found ${ranges.length} rw- regions (from ${rawRanges.length} total), sorted by size desc`);
    send({
        type: 'status',
        message: `Scanning ${ranges.length} memory regions...`,
        total_regions: ranges.length
    });

    // ── Helper: read a MsgPack string at position ─────────────────────
    // Returns {str, nextPos} or null
    function readMsgPackStr(view, pos) {
        if (pos >= view.length) return null;
        const b = view[pos];
        
        // fixstr: 0xA0-0xBF, length = b & 0x1F
        if (b >= 0xA0 && b <= 0xBF) {
            const len = b & 0x1F;
            if (pos + 1 + len > view.length) return null;
            let s = '';
            for (let i = 0; i < len; i++) {
                s += String.fromCharCode(view[pos + 1 + i]);
            }
            return { str: s, nextPos: pos + 1 + len };
        }
        
        // str8: 0xD9, 1-byte length
        if (b === 0xD9 && pos + 2 <= view.length) {
            const len = view[pos + 1];
            if (pos + 2 + len > view.length) return null;
            let s = '';
            for (let i = 0; i < len; i++) {
                s += String.fromCharCode(view[pos + 2 + i]);
            }
            return { str: s, nextPos: pos + 2 + len };
        }
        
        // str16: 0xDA, 2-byte length
        if (b === 0xDA && pos + 3 <= view.length) {
            const len = (view[pos + 1] << 8) | view[pos + 2];
            if (len > 1000) return null; // sanity: skip absurdly long strings
            if (pos + 3 + len > view.length) return null;
            let s = '';
            for (let i = 0; i < len; i++) {
                s += String.fromCharCode(view[pos + 3 + i]);
            }
            return { str: s, nextPos: pos + 3 + len };
        }
        
        return null;
    }
    
    // ── Helper: read array header at position ─────────────────────────
    // Returns {len, nextPos} or null
    function readArrayHeader(view, pos) {
        if (pos >= view.length) return null;
        const b = view[pos];
        
        // fixarray: 0x90-0x9F
        if (b >= 0x90 && b <= 0x9F) {
            return { len: b - 0x90, nextPos: pos + 1 };
        }
        // array16: 0xDC
        if (b === 0xDC && pos + 3 <= view.length) {
            return { len: (view[pos+1] << 8) | view[pos+2], nextPos: pos + 3 };
        }
        // array32: 0xDD
        if (b === 0xDD && pos + 5 <= view.length) {
            return { len: (((view[pos+1] << 24) >>> 0) + (view[pos+2] << 16) + (view[pos+3] << 8) + view[pos+4]) >>> 0, nextPos: pos + 5 };
        }
        return null;
    }
    
    // ── Helper: read map header at position ───────────────────────────
    function readMapHeader(view, pos) {
        if (pos >= view.length) return null;
        const b = view[pos];
        
        // fixmap: 0x80-0x8F
        if (b >= 0x80 && b <= 0x8F) {
            return { len: b - 0x80, nextPos: pos + 1 };
        }
        // map16: 0xDE
        if (b === 0xDE && pos + 3 <= view.length) {
            return { len: (view[pos+1] << 8) | view[pos+2], nextPos: pos + 3 };
        }
        // map32: 0xDF
        if (b === 0xDF && pos + 5 <= view.length) {
            return { len: (((view[pos+1] << 24) >>> 0) + (view[pos+2] << 16) + (view[pos+3] << 8) + view[pos+4]) >>> 0, nextPos: pos + 5 };
        }
        return null;
    }
    
    // ── Helper: check if byte is a valid MsgPack string start ─────────
    function isStringStart(b) {
        return (b >= 0xA0 && b <= 0xBF) || b === 0xD9 || b === 0xDA;
    }
    
    // ── Helper: check if string looks like a valid key name ───────────
    // (ASCII, snake_case or camelCase, reasonable length)
    function isLikelyKeyName(s) {
        if (s.length < 2 || s.length > 80) return false;
        // Must be printable ASCII
        for (let i = 0; i < s.length; i++) {
            const c = s.charCodeAt(i);
            if (c < 0x20 || c > 0x7E) return false;
        }
        // Must start with a letter or underscore
        if (!/^[a-zA-Z_]/.test(s)) return false;
        // Should look like an identifier (allow letters, digits, underscore)
        if (!/^[a-zA-Z0-9_]+$/.test(s)) return false;
        return true;
    }

    // ── Collect interesting key names with context ─────────────────────
    // Map of keyName -> { count, regions, valueTypes (set of what follows), arrayLengths, subKeys }
    const keyData = {};  // keyName -> { count, regions: Set, arrayInfo: [{len, subKeys}] }
    const regionFindings = [];
    
    let scannedCount = 0;
    
    for (let ri = 0; ri < ranges.length; ri++) {
        const range = ranges[ri];
        scannedCount++;
        
        if (scannedCount % 20 === 0 || scannedCount === 1) {
            send({
                type: 'progress',
                scanned: scannedCount,
                total: ranges.length
            });
            console.log(`Progress: ${scannedCount}/${ranges.length} regions...`);
        }
        
        try {
            const readSize = Math.min(range.size, maxBytesToScan);
            const data = range.base.readByteArray(readSize);
            if (!data) continue;
            
            const view = new Uint8Array(data);
            const regionKeys = new Set();
            
            // Scan for string keys followed by interesting values
            for (let i = 0; i < view.length - 4; i++) {
                // Look for MsgPack string markers
                if (!isStringStart(view[i])) continue;
                
                const strResult = readMsgPackStr(view, i);
                if (!strResult) continue;
                if (!isLikelyKeyName(strResult.str)) continue;
                
                const keyName = strResult.str;
                const valuePos = strResult.nextPos;
                
                // Check what follows this key
                if (valuePos >= view.length) continue;
                const valueByte = view[valuePos];
                
                // We're interested in keys whose value is an array or a map
                // but also record all keys for a full picture
                let valueType = 'other';
                let arrayInfo = null;
                
                // Array value?
                const arrHeader = readArrayHeader(view, valuePos);
                if (arrHeader && arrHeader.len > 0 && arrHeader.len < 100000) {
                    valueType = 'array';
                    // Try to peek at sub-keys in first element
                    const subKeys = [];
                    const mapHeader = readMapHeader(view, arrHeader.nextPos);
                    if (mapHeader && mapHeader.len > 0 && mapHeader.len < 200) {
                        // Read up to 20 key names from the first map element
                        let subPos = mapHeader.nextPos;
                        for (let k = 0; k < Math.min(mapHeader.len, 20); k++) {
                            const subStr = readMsgPackStr(view, subPos);
                            if (!subStr) break;
                            if (isLikelyKeyName(subStr.str)) {
                                subKeys.push(subStr.str);
                            }
                            // Skip past this key-value pair (rough: jump forward)
                            // We can't perfectly skip values without a full parser,
                            // so just scan forward for next string start
                            let nextKeyPos = subStr.nextPos;
                            // Skip the value: look for the next string start that's a valid key
                            for (let skip = nextKeyPos; skip < Math.min(nextKeyPos + 500, view.length); skip++) {
                                if (isStringStart(view[skip])) {
                                    const test = readMsgPackStr(view, skip);
                                    if (test && isLikelyKeyName(test.str)) {
                                        nextKeyPos = skip;
                                        break;
                                    }
                                }
                            }
                            if (nextKeyPos === subStr.nextPos) break; // couldn't advance
                            subPos = nextKeyPos;
                        }
                    }
                    arrayInfo = { len: arrHeader.len, subKeys: subKeys };
                }
                // Map value?
                else if (readMapHeader(view, valuePos)) {
                    valueType = 'map';
                }
                // Integer/bool/nil are less interesting but still record the key
                
                // Store finding
                if (!keyData[keyName]) {
                    keyData[keyName] = { count: 0, regions: [], arrayInfos: [], valueTypes: [] };
                }
                keyData[keyName].count++;
                if (!keyData[keyName].regions.includes(ri)) {
                    keyData[keyName].regions.push(ri);
                }
                if (!keyData[keyName].valueTypes.includes(valueType)) {
                    keyData[keyName].valueTypes.push(valueType);
                }
                if (arrayInfo) {
                    // Only keep unique array lengths to avoid duplicates
                    const isDup = keyData[keyName].arrayInfos.some(
                        a => a.len === arrayInfo.len && JSON.stringify(a.subKeys) === JSON.stringify(arrayInfo.subKeys)
                    );
                    if (!isDup) {
                        keyData[keyName].arrayInfos.push(arrayInfo);
                    }
                }
                
                regionKeys.add(keyName);
                
                // Skip past this string to avoid re-reading sub-bytes
                i = strResult.nextPos - 1;
            }
            
            if (regionKeys.size > 0) {
                regionFindings.push({
                    regionIndex: ri,
                    regionSize: range.size,
                    keyCount: regionKeys.size,
                    keys: Array.from(regionKeys).slice(0, 50) // cap for message size
                });
            }
            
        } catch (e) {
            // Skip unreadable regions
            continue;
        }
    }
    
    // ── Build results ─────────────────────────────────────────────────
    
    // Sort keys: prioritize those with array values and high counts
    const sortedKeys = Object.entries(keyData)
        .map(([name, info]) => ({
            name,
            count: info.count,
            regionCount: info.regions.length,
            valueTypes: info.valueTypes,
            arrayInfos: info.arrayInfos
        }))
        .sort((a, b) => {
            // Array keys first
            const aHasArray = a.valueTypes.includes('array') ? 1 : 0;
            const bHasArray = b.valueTypes.includes('array') ? 1 : 0;
            if (aHasArray !== bHasArray) return bHasArray - aHasArray;
            // Then by count
            return b.count - a.count;
        });
    
    // ── Report: Array keys (most interesting for extraction) ──────────
    const arrayKeys = sortedKeys.filter(k => k.valueTypes.includes('array'));
    
    console.log(`\n========================================`);
    console.log(`RESULTS: Found ${sortedKeys.length} unique key names`);
    console.log(`         ${arrayKeys.length} keys point to arrays`);
    console.log(`========================================\n`);
    
    if (arrayKeys.length > 0) {
        console.log(`--- ARRAY KEYS (most useful for extraction) ---`);
        for (const key of arrayKeys.slice(0, 50)) {
            console.log(`  "${key.name}" -> array`);
            for (const ai of key.arrayInfos) {
                console.log(`    length: ${ai.len}, sub-keys: [${ai.subKeys.join(', ')}]`);
            }
        }
    }
    
    console.log(`\n--- ALL KEYS (top 100 by frequency) ---`);
    for (const key of sortedKeys.slice(0, 100)) {
        const types = key.valueTypes.join('/');
        console.log(`  "${key.name}" (${types}) x${key.count} in ${key.regionCount} regions`);
    }
    
    // ── Send full results back to Python ──────────────────────────────
    send({
        type: 'results',
        total_keys: sortedKeys.length,
        array_key_count: arrayKeys.length,
        array_keys: arrayKeys.slice(0, 100),
        all_keys: sortedKeys.slice(0, 300),
        region_findings: regionFindings.slice(0, 50)
    });
    
    console.log("\nExploration complete! Check explore_results.json for full data.");
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
    print("  Uma Musume Memory Explorer")
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
                    scanned = payload.get("scanned", 0)
                    total = payload.get("total", 0)
                    pct = int(scanned / total * 100) if total else 0
                    print(f"[*] Scanning... {scanned}/{total} regions ({pct}%)", end="\r")

                elif ptype == "results":
                    results_data = payload
                    scan_done = True
                    print()  # newline after progress \r

                else:
                    # Unknown payload, just print it
                    print(f"[JS] {payload}")

            elif isinstance(payload, str):
                print(f"[JS] {payload}")

        elif msg_type == "error":
            script_error = message
            print(f"[X] JS Error: {message.get('description', 'unknown')}")
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
        script.load()
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
            print(f"[*] Still running... {i + 1}s elapsed")

    if script_error and not results_data:
        print("[X] Explorer failed with a script error. See above.")
        sys.exit(1)

    if not results_data:
        print("[X] Explorer timed out without producing results.")
        print("    The game may have too much memory to scan in time.")
        print("    Try closing other apps and running again.")
        sys.exit(1)

    # ── Print summary ──────────────────────────────────────────────────
    total_keys = results_data.get("total_keys", 0)
    array_keys = results_data.get("array_keys", [])

    print()
    print("=" * 60)
    print(f"  RESULTS: {total_keys} unique keys found")
    print(f"  {len(array_keys)} keys point to arrays (extractable data)")
    print("=" * 60)
    print()

    if array_keys:
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  ARRAY KEYS — These are what you can extract!          ║")
        print("╚══════════════════════════════════════════════════════════╝")
        for key in array_keys:
            name = key["name"]
            for ai in key.get("arrayInfos", []):
                arr_len = ai.get("len", "?")
                sub = ai.get("subKeys", [])
                print(f'\n  📦 "{name}"  (array of {arr_len} items)')
                if sub:
                    print(f"     Sub-keys: {', '.join(sub)}")

                # Print the hex pattern they'd need
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
        print()

    # ── Save to JSON ───────────────────────────────────────────────────
    output_file = os.path.abspath("explore_results.json")
    try:
        # Build a clean output
        output = {
            "summary": {
                "total_keys": total_keys,
                "array_key_count": len(array_keys),
            },
            "array_keys": array_keys,
            "all_keys": results_data.get("all_keys", []),
            "region_findings": results_data.get("region_findings", []),
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"[OK] Full results saved to: {output_file}")
    except Exception as e:
        print(f"[!] Could not save results: {e}")
        # Print JSON to stdout as fallback
        print(json.dumps(results_data, indent=2))

    print()
    print("Next steps:")
    print('  1. Look at the array keys above — find the one for your target data')
    print('  2. Copy the "Pattern" hex string into your extractor script')
    print('  3. Use the "Offset" value for the arrayStart calculation')
    print('  4. Pick a sub-key for validation (like "card_id" in the veteran extractor)')


if __name__ == "__main__":
    main()

