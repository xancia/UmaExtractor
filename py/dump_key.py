# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
"""
Uma Musume Key Dumper
=====================
Extracts and displays the actual contents of a MsgPack key from game memory.
Use this after running explore_memory.py to see what's inside an array/map.

Usage:
  python dump_key.py                          # defaults to "skill_array"
  python dump_key.py skill_array
  python dump_key.py support_card_list
  python dump_key.py succession_chara_array

  # Dump multiple keys at once:
  python dump_key.py skill_array support_card_list race_result_list
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
MAX_WAIT_SECONDS = 600


def build_scan_script(key_names):
    """
    Build a Frida JS script that scans for one or more MsgPack key names,
    reads the value bytes, and sends them back to Python for deserialization.
    """
    # Build pattern info for each key
    key_configs = []
    for name in key_names:
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
        key_configs.append({
            "name": name,
            "hex": hex_pattern,
            "offset": offset,
        })

    configs_json = json.dumps(key_configs)

    return r"""
console.log("=== Uma Musume Key Dumper ===");

(function() {
    const keyConfigs = """ + configs_json + r""";
    const scanProtection = "rw-";
    const minRangeSize = 16 * 1024;
    const maxRangeSize = 500 * 1024 * 1024;
    // Try reading up to these sizes to capture the full array
    const probeSizes = [1 * 1024 * 1024, 5 * 1024 * 1024, 15 * 1024 * 1024, 25 * 1024 * 1024];

    const rawRanges = Process.enumerateRanges({protection: scanProtection, coalesce: true});
    const ranges = [];
    for (const r of rawRanges) {
        if (r.size >= minRangeSize && r.size <= maxRangeSize) {
            ranges.push(r);
        }
    }
    ranges.sort((a, b) => b.size - a.size);

    console.log(`Scanning ${ranges.length} memory regions for ${keyConfigs.length} key(s)...`);
    send({ type: 'status', message: `Scanning ${ranges.length} regions for ${keyConfigs.length} key(s)...` });

    const foundKeys = new Set();

    for (const config of keyConfigs) {
        console.log(`\nSearching for "${config.name}" (pattern: ${config.hex})...`);
        let found = false;

        for (let ri = 0; ri < ranges.length && !found; ri++) {
            const range = ranges[ri];

            if (ri % 100 === 0) {
                send({ type: 'progress', key: config.name, scanned: ri, total: ranges.length });
            }

            try {
                const results = Memory.scanSync(range.base, range.size, config.hex);

                for (const result of results) {
                    if (found) break;

                    const arrayStart = result.address.add(config.offset);

                    for (const probeSize of probeSizes) {
                        try {
                            const maxSize = Math.min(probeSize, range.size - (arrayStart - range.base));
                            if (maxSize <= 0) continue;
                            const data = arrayStart.readByteArray(maxSize);

                            const view = new Uint8Array(data);
                            if (view.length < 1) continue;

                            // Validate MsgPack header (array, map, or scalar)
                            const first = view[0];
                            let valid = false;
                            let arrayLen = -1;

                            // Array headers
                            if (first >= 0x90 && first <= 0x9F) {
                                arrayLen = first - 0x90;
                                valid = true;
                            } else if (first === 0xDC && view.length >= 3) {
                                arrayLen = (view[1] << 8) | view[2];
                                valid = true;
                            } else if (first === 0xDD && view.length >= 5) {
                                arrayLen = (((view[1] << 24) >>> 0) + (view[2] << 16) + (view[3] << 8) + view[4]) >>> 0;
                                valid = true;
                            }
                            // Map headers
                            else if (first >= 0x80 && first <= 0x8F) { valid = true; }
                            else if (first === 0xDE || first === 0xDF) { valid = true; }
                            // Scalar values (nil, bool, int, fixstr, etc.)
                            else if (first <= 0x7F || first >= 0xC0) { valid = true; }

                            if (!valid) continue;

                            console.log(`Found "${config.name}"! Sending ${view.length} bytes (array len=${arrayLen})`);
                            send({
                                type: 'found',
                                key: config.name,
                                array_len: arrayLen,
                                byte_count: view.length,
                                region_index: ri
                            }, data);

                            found = true;
                            foundKeys.add(config.name);
                            break;

                        } catch(e) {
                            continue;
                        }
                    }
                }
            } catch(e) {
                continue;
            }
        }

        if (!found) {
            console.log(`"${config.name}" not found in memory.`);
            send({ type: 'not_found', key: config.name });
        }
    }

    send({ type: 'done', found_count: foundKeys.size, total: keyConfigs.length });
    console.log(`\nDone! Found ${foundKeys.size}/${keyConfigs.length} keys.`);
})();
"""


# ── Process attachment ─────────────────────────────────────────────────────

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
        if any(kw in name for kw in PROCESS_KEYWORDS):
            candidates.append(proc)
    candidates.sort(key=lambda p: (p.name or "").lower())
    return candidates


def attach_to_game():
    attach_errors = []
    for process_name in TARGET_PROCESS_NAMES:
        try:
            session = frida.attach(process_name)
            print(f"[OK] Attached: {process_name}")
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
                print(f"[OK] Attached: {proc.name} (pid {proc.pid})")
                return session
            except Exception as e:
                attach_errors.append((f"{proc.name} (pid {proc.pid})", e))

    print("[X] Could not attach to game process.")
    for target, err in attach_errors:
        print(f"    - {target}: {type(err).__name__}: {err}")
    return None


# ── Main ───────────────────────────────────────────────────────────────────

# PII fields to strip before saving
PII_FIELDS = ["viewer_id", "owner_viewer_id", "dmm_viewer_id"]


def main():
    # Parse key names from args, default to skill_array
    key_names = sys.argv[1:] if len(sys.argv) > 1 else ["skill_array"]

    print("=" * 60)
    print("  Uma Musume Key Dumper")
    print(f"  Target keys: {', '.join(key_names)}")
    print("=" * 60)
    print()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    # Collect results: key_name -> decoded data
    results = {}
    pending = set(key_names)
    done = False
    script_error = None

    def on_message(message, data):
        nonlocal done, script_error

        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                ptype = payload.get("type")

                if ptype == "found" and data:
                    key = payload["key"]
                    byte_count = payload.get("byte_count", len(data))
                    array_len = payload.get("array_len", "?")
                    print(f"\n[OK] Found \"{key}\" — {byte_count} bytes, array length: {array_len}")

                    # Deserialize with msgpack
                    try:
                        unpacker = msgpack.Unpacker(raw=False)
                        unpacker.feed(data)
                        decoded = unpacker.unpack()
                        results[key] = decoded
                        pending.discard(key)

                        # Print preview
                        if isinstance(decoded, list):
                            print(f"     Array with {len(decoded)} items")
                            for i, item in enumerate(decoded[:5]):
                                preview = json.dumps(item, ensure_ascii=False, default=str)
                                if len(preview) > 200:
                                    preview = preview[:200] + "..."
                                print(f"     [{i}] {preview}")
                            if len(decoded) > 5:
                                print(f"     ... and {len(decoded) - 5} more items")
                        elif isinstance(decoded, dict):
                            print(f"     Map with {len(decoded)} keys: {list(decoded.keys())[:20]}")
                        else:
                            print(f"     Value: {decoded}")

                    except Exception as e:
                        print(f"[!] Failed to deserialize \"{key}\": {type(e).__name__}: {e}")

                elif ptype == "not_found":
                    key = payload["key"]
                    print(f"\n[!] \"{key}\" not found in memory")
                    pending.discard(key)

                elif ptype == "progress":
                    key = payload.get("key", "")
                    scanned = payload.get("scanned", 0)
                    total = payload.get("total", 0)
                    if total > 0:
                        pct = int(scanned / total * 100)
                        print(f"[*] Searching \"{key}\"... {pct}% ({scanned}/{total})", end="\r")

                elif ptype == "done":
                    done = True
                    print()

                elif ptype == "status":
                    print(f"[*] {payload.get('message', '')}")

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

    scan_script = build_scan_script(key_names)

    try:
        script = session.create_script(scan_script, runtime="v8")
        script.on("message", on_message)
        print("[*] Loading scanner...")
        try:
            script.load()
        except Exception as e:
            if "timeout" in str(e).lower():
                print("[*] Script load timed out, scan continues in background...")
            else:
                raise
    except Exception as e:
        print(f"[X] Failed to load script: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.exit(1)

    print(f"[*] Waiting for results (up to {MAX_WAIT_SECONDS}s)...")
    for i in range(MAX_WAIT_SECONDS):
        time.sleep(1)
        if done or script_error:
            break
        if (i + 1) % 30 == 0:
            print(f"\n[*] Still running... {i + 1}s elapsed")

    # ── Print & save results ───────────────────────────────────────────
    if not results:
        print("\n[X] No data was extracted.")
        if script_error:
            print("    A script error occurred — see above.")
        print("    Make sure you're on the right page in-game.")
        sys.exit(1)

    print()
    print("=" * 60)
    print(f"  EXTRACTED {len(results)} key(s)")
    print("=" * 60)

    # Strip PII
    for key, data in results.items():
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for pii in PII_FIELDS:
                        item.pop(pii, None)
        elif isinstance(data, dict):
            for pii in PII_FIELDS:
                data.pop(pii, None)

    # Save each key to its own file, plus a combined file
    for key, data in results.items():
        filename = f"{key}.json"
        filepath = os.path.abspath(filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            count = len(data) if isinstance(data, list) else "N/A"
            print(f"\n[OK] {key}: saved to {filename} ({count} items)")

            # Print full contents for small arrays
            if isinstance(data, list) and len(data) <= 30:
                print(json.dumps(data, indent=2, ensure_ascii=False))

        except Exception as e:
            print(f"[!] Failed to save {filename}: {e}")

    if len(results) > 1:
        combined_path = os.path.abspath("dump_all.json")
        try:
            with open(combined_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\n[OK] Combined dump saved to: {combined_path}")
        except Exception as e:
            print(f"[!] Failed to save combined dump: {e}")


if __name__ == "__main__":
    main()

