# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
"""
Uma Musume Array Hunter
========================
Scans game memory for MsgPack arrays that contain specific known values.
Instead of guessing key names, we search for the actual data.

Usage:
  python hunt_array.py
  (edit KNOWN_IDS below with IDs you expect to find in the target array)
"""
import json
import os
import sys
import time
import traceback

import frida
import msgpack

# ── Config ─────────────────────────────────────────────────────────────────

TARGET_PROCESS_NAMES = [
    "UmamusumePrettyDerby.exe",
    "UmamusumePrettyDerby",
]
PROCESS_KEYWORDS = ["uma", "musume", "derby", "cygames"]
MAX_WAIT_SECONDS = 30000

# IDs we know should be in the target array.
# The script will find every MsgPack-encoded occurrence of each ID,
# then figure out which array/region contains the most of them.
KNOWN_IDS = [200154, 200152, 200441, 200652, 200722, 201152]


def build_hunt_script(known_ids):
    """
    Build a Frida JS script that:
    1. Encodes each known ID as all possible MsgPack int representations
    2. Scans memory for each encoding
    3. For each hit, reads surrounding bytes to find the enclosing array
    4. Reports which regions/arrays contain the most hits
    """
    ids_json = json.dumps(known_ids)

    return r"""
console.log("=== Uma Musume Array Hunter ===");
console.log("Searching for arrays containing known IDs...");

(function() {
    const knownIds = """ + ids_json + r""";
    const scanProtection = "rw-";
    const minRangeSize = 16 * 1024;
    const maxRangeSize = 500 * 1024 * 1024;

    // ── Encode an integer as MsgPack hex patterns ─────────────────────
    // MsgPack can encode the same int multiple ways; we generate all
    // likely representations the game might use.
    function intToMsgPackPatterns(val) {
        const patterns = [];

        // MsgPack uint32: CE xx xx xx xx
        if (val >= 0 && val <= 0xFFFFFFFF) {
            const b3 = (val >>> 24) & 0xFF;
            const b2 = (val >>> 16) & 0xFF;
            const b1 = (val >>> 8) & 0xFF;
            const b0 = val & 0xFF;
            patterns.push({
                label: `msgpack_uint32(${val})`,
                hex: `CE ${hex(b3)} ${hex(b2)} ${hex(b1)} ${hex(b0)}`,
                size: 5
            });
        }
        // MsgPack uint16: CD xx xx
        if (val >= 0 && val <= 0xFFFF) {
            const hi = (val >>> 8) & 0xFF;
            const lo = val & 0xFF;
            patterns.push({
                label: `msgpack_uint16(${val})`,
                hex: `CD ${hex(hi)} ${hex(lo)}`,
                size: 3
            });
        }
        // MsgPack uint8: CC xx
        if (val >= 0 && val <= 0xFF) {
            patterns.push({
                label: `msgpack_uint8(${val})`,
                hex: `CC ${hex(val)}`,
                size: 2
            });
        }
        // MsgPack positive fixint: 00-7F
        if (val >= 0 && val <= 127) {
            patterns.push({
                label: `msgpack_fixint(${val})`,
                hex: hex(val),
                size: 1
            });
        }
        // MsgPack int32: D2 xx xx xx xx (signed, big-endian)
        if (val >= -2147483648 && val <= 2147483647) {
            const v = val < 0 ? val + 0x100000000 : val;
            const b3 = (v >>> 24) & 0xFF;
            const b2 = (v >>> 16) & 0xFF;
            const b1 = (v >>> 8) & 0xFF;
            const b0 = v & 0xFF;
            patterns.push({
                label: `msgpack_int32(${val})`,
                hex: `D2 ${hex(b3)} ${hex(b2)} ${hex(b1)} ${hex(b0)}`,
                size: 5
            });
        }

        // Raw little-endian int32 (C#/Unity native memory layout)
        if (val >= 0 && val <= 0xFFFFFFFF) {
            const b0 = val & 0xFF;
            const b1 = (val >>> 8) & 0xFF;
            const b2 = (val >>> 16) & 0xFF;
            const b3 = (val >>> 24) & 0xFF;
            patterns.push({
                label: `raw_le32(${val})`,
                hex: `${hex(b0)} ${hex(b1)} ${hex(b2)} ${hex(b3)}`,
                size: 4
            });
        }

        return patterns;
    }

    function hex(b) {
        return ('0' + b.toString(16).toUpperCase()).slice(-2);
    }

    // ── Collect memory regions ────────────────────────────────────────
    const rawRanges = Process.enumerateRanges({protection: scanProtection, coalesce: true});
    const ranges = [];
    for (const r of rawRanges) {
        if (r.size >= minRangeSize && r.size <= maxRangeSize) {
            ranges.push(r);
        }
    }
    ranges.sort((a, b) => b.size - a.size);

    console.log(`${ranges.length} scannable regions (from ${rawRanges.length} total)`);

    // ── For each known ID, find all memory locations ──────────────────
    // Track which regions contain hits: regionIndex -> Set of matched IDs
    const regionHits = {};  // regionIndex -> { ids: Set, addresses: [] }

    let totalScans = 0;
    const allPatterns = [];
    for (const id of knownIds) {
        const patterns = intToMsgPackPatterns(id);
        for (const p of patterns) {
            allPatterns.push({ id, ...p });
        }
    }

    const totalWork = allPatterns.length * ranges.length;
    console.log(`Scanning ${allPatterns.length} patterns x ${ranges.length} regions = ${totalWork} scans...`);
    send({ type: 'status', message: `Hunting for ${knownIds.length} IDs across ${ranges.length} regions...` });

    for (const pat of allPatterns) {
        for (let ri = 0; ri < ranges.length; ri++) {
            totalScans++;
            if (totalScans % 500 === 0) {
                const pct = Math.round(totalScans / totalWork * 100);
                send({ type: 'progress', pct, scanned: totalScans, total: totalWork });
            }

            const range = ranges[ri];
            try {
                const results = Memory.scanSync(range.base, range.size, pat.hex);
                if (results.length > 0) {
                    if (!regionHits[ri]) {
                        regionHits[ri] = { ids: new Set(), addresses: [], rangeBase: range.base, rangeSize: range.size };
                    }
                    regionHits[ri].ids.add(pat.id);
                    for (const r of results) {
                        regionHits[ri].addresses.push({
                            id: pat.id,
                            address: r.address,
                            encoding: pat.label
                        });
                    }
                }
            } catch(e) {
                continue;
            }
        }
    }

    // ── Find regions with the most matching IDs ───────────────────────
    const regionScores = Object.entries(regionHits)
        .map(([ri, info]) => ({
            regionIndex: parseInt(ri),
            matchedIdCount: info.ids.size,
            matchedIds: Array.from(info.ids),
            totalHits: info.addresses.length,
            rangeBase: info.rangeBase,
            rangeSize: info.rangeSize,
            addresses: info.addresses
        }))
        .sort((a, b) => b.matchedIdCount - a.matchedIdCount || b.totalHits - a.totalHits);

    console.log(`\n========================================`);
    console.log(`RESULTS: ${regionScores.length} regions contain at least one target ID`);
    console.log(`========================================\n`);

    // Show top regions
    for (const region of regionScores.slice(0, 10)) {
        console.log(`Region #${region.regionIndex}: ${region.matchedIdCount}/${knownIds.length} IDs matched, ${region.totalHits} total hits, size=${region.rangeSize}`);
        for (const addr of region.addresses.slice(0, 20)) {
            console.log(`  ID ${addr.id} (${addr.encoding}) at ${addr.address}`);
        }
    }

    // ── For the best region(s), try to extract data ───────────────────
    // Only consider regions that contain ALL known IDs
    const bestRegions = regionScores.filter(r => r.matchedIdCount === knownIds.length).slice(0, 3);

    if (bestRegions.length === 0) {
        // Fall back to regions with the most matches
        const fallback = regionScores.filter(r => r.matchedIdCount >= Math.max(2, knownIds.length - 1)).slice(0, 3);
        if (fallback.length > 0) {
            console.log(`No region has ALL ${knownIds.length} IDs. Falling back to best partial matches...`);
            for (const r of fallback) bestRegions.push(r);
        } else if (regionScores.length > 0) {
            console.log(`No region has enough IDs. Sending best available...`);
            bestRegions.push(regionScores[0]);
        }
    }

    for (const region of bestRegions) {
        // Find the range of addresses where our IDs were found
        let minAddr = region.addresses[0].address;
        let maxAddr = region.addresses[0].address;
        for (const a of region.addresses) {
            if (a.address.compare(minAddr) < 0) minAddr = a.address;
            if (a.address.compare(maxAddr) > 0) maxAddr = a.address;
        }

        // Read from well before the first hit to well after the last
        const readBefore = 16 * 1024;      // 16 KB before first hit
        const readAfter = 2 * 1024 * 1024; // 2 MB after last hit
        const readStart = minAddr.sub(readBefore);
        const clampedStart = readStart.compare(region.rangeBase) < 0 ? region.rangeBase : readStart;
        const span = maxAddr.sub(clampedStart).toInt32() + readAfter;
        const maxRead = Math.min(span, region.rangeSize - clampedStart.sub(region.rangeBase).toInt32(), 25 * 1024 * 1024);

        if (maxRead <= 0) continue;

        try {
            const data = clampedStart.readByteArray(maxRead);
            console.log(`\nSending ${maxRead} bytes from best region #${region.regionIndex} (${region.matchedIdCount} IDs matched)`);

            send({
                type: 'region_data',
                region_index: region.regionIndex,
                matched_id_count: region.matchedIdCount,
                matched_ids: region.matchedIds,
                total_hits: region.totalHits,
                range_size: region.rangeSize,
                read_size: maxRead
            }, data);

        } catch(e) {
            console.log(`Failed to read region #${region.regionIndex}: ${e}`);
        }
    }

    send({
        type: 'done',
        regions_with_hits: regionScores.length,
        top_regions: regionScores.slice(0, 20).map(r => ({
            regionIndex: r.regionIndex,
            matchedIdCount: r.matchedIdCount,
            matchedIds: r.matchedIds,
            totalHits: r.totalHits,
            rangeSize: r.rangeSize
        }))
    });

    console.log("\nHunt complete!");
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


# ── MsgPack structure finder ──────────────────────────────────────────────

def deep_find_ids(obj, known_set, found=None, depth=0):
    """Recursively search any decoded MsgPack structure for known IDs."""
    if found is None:
        found = set()
    if depth > 20:
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


def find_msgpack_structures(raw_bytes, known_ids):
    """
    Walk through raw bytes looking for MsgPack arrays AND maps that contain
    the known IDs. Try deserializing at various offsets.
    """
    results = []
    known_set = set(known_ids)
    data_len = len(raw_bytes)
    last_print = time.time()
    start_time = time.time()
    max_seconds = 120  # give up after 2 minutes per region
    attempts = 0
    skipped = 0

    print(f"    Scanning {data_len:,} bytes for MsgPack structures...")

    i = 0
    while i < data_len - 3:
        # Progress every 2 seconds
        now = time.time()
        if now - last_print >= 2:
            pct = int(i / data_len * 100)
            print(f"    ... {pct}% ({i:,}/{data_len:,} bytes, {attempts} attempts, {len(results)} found)", flush=True)
            last_print = now
        if now - start_time > max_seconds:
            print(f"    ⏱ Time limit ({max_seconds}s) reached at {int(i/data_len*100)}%, returning {len(results)} results so far")
            break

        b = raw_bytes[i]

        # Check for array or map headers
        container_type = None

        # Array: fixarray 0x90-0x9F, array16 0xDC, array32 0xDD
        if 0x90 <= b <= 0x9F or b == 0xDC or b == 0xDD:
            container_type = "array"
        # Map: fixmap 0x80-0x8F, map16 0xDE, map32 0xDF
        elif 0x80 <= b <= 0x8F or b == 0xDE or b == 0xDF:
            container_type = "map"

        if not container_type:
            i += 1
            continue

        # Quick size check: skip tiny containers (fixarray/fixmap with 0-1 items)
        if container_type == "array" and 0x90 <= b <= 0x91:
            i += 1
            continue
        if container_type == "map" and 0x80 <= b <= 0x81:
            i += 1
            continue

        attempts += 1
        try:
            chunk = raw_bytes[i:min(i + 25 * 1024 * 1024, data_len)]
            unpacker = msgpack.Unpacker(raw=False, max_buffer_size=50 * 1024 * 1024)
            unpacker.feed(chunk)
            decoded = unpacker.unpack()

            if decoded is None:
                i += 1
                continue

            # For maps/lists, check size
            if isinstance(decoded, (list, dict)) and len(decoded) == 0:
                i += 1
                continue

            # Deep search for known IDs anywhere in the structure
            found_ids = deep_find_ids(decoded, known_set)

            if len(found_ids) == len(known_set):
                # Describe what we found
                if isinstance(decoded, list):
                    desc = f"array[{len(decoded)}]"
                elif isinstance(decoded, dict):
                    desc = f"map[{len(decoded)} keys]"
                else:
                    desc = type(decoded).__name__

                print(f"    ✅ HIT at offset {i}: {desc} with {len(found_ids)} IDs: {sorted(found_ids)}")

                results.append({
                    "offset": i,
                    "container_type": container_type,
                    "description": desc,
                    "found_ids": sorted(found_ids),
                    "found_count": len(found_ids),
                    "data": decoded,
                })

                # Skip past this entire structure to avoid finding subsets
                # Estimate consumed bytes from the unpacker
                try:
                    consumed = unpacker.tell()
                    if consumed > 10:
                        i += consumed
                        skipped += consumed
                        continue
                except Exception:
                    pass

            i += 1

        except (msgpack.UnpackValueError, msgpack.FormatError, msgpack.StackError):
            i += 1
            continue
        except Exception:
            i += 1
            continue

    elapsed = time.time() - start_time
    print(f"    Done: {attempts} attempts, {len(results)} structures found in {elapsed:.1f}s")

    # Sort by how many known IDs were found
    results.sort(key=lambda r: r["found_count"], reverse=True)
    return results


def dump_raw_context(raw_bytes, known_ids):
    """
    When MsgPack deserialization fails, look for known IDs as raw little-endian
    int32s and dump the surrounding bytes for manual inspection.
    """
    import struct
    contexts = []
    for target_id in known_ids:
        target_bytes = struct.pack("<I", target_id)
        pos = 0
        while True:
            idx = raw_bytes.find(target_bytes, pos)
            if idx == -1:
                break
            # Read 64 bytes before and after
            start = max(0, idx - 64)
            end = min(len(raw_bytes), idx + 68)
            snippet = raw_bytes[start:end]
            contexts.append({
                "id": target_id,
                "offset": idx,
                "hex_dump": " ".join(f"{b:02X}" for b in snippet),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in snippet),
            })
            pos = idx + 4  # keep searching
    return contexts


# ── Main ───────────────────────────────────────────────────────────────────

PII_FIELDS = ["viewer_id", "owner_viewer_id", "dmm_viewer_id"]


def main():
    print("=" * 60)
    print("  Uma Musume Array Hunter")
    print(f"  Looking for arrays containing: {KNOWN_IDS}")
    print("=" * 60)
    print()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    region_chunks = []  # list of (metadata, raw_bytes)
    done = False
    script_error = None
    done_payload = None

    def on_message(message, data):
        nonlocal done, script_error, done_payload

        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                ptype = payload.get("type")

                if ptype == "region_data" and data:
                    print(f"\n[OK] Received {len(data)} bytes from region #{payload.get('region_index')}")
                    print(f"     Matched {payload.get('matched_id_count')}/{len(KNOWN_IDS)} IDs: {payload.get('matched_ids')}")
                    region_chunks.append((payload, data))

                elif ptype == "progress":
                    pct = payload.get("pct", 0)
                    print(f"[*] Hunting... {pct}%", end="\r")

                elif ptype == "status":
                    print(f"[*] {payload.get('message', '')}")

                elif ptype == "done":
                    done = True
                    done_payload = payload
                    print()

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

    hunt_script = build_hunt_script(KNOWN_IDS)

    try:
        script = session.create_script(hunt_script, runtime="v8")
        script.on("message", on_message)
        print("[*] Loading hunter script...")
        try:
            script.load()
        except Exception as e:
            if "timeout" in str(e).lower():
                print("[*] Script load timed out, hunt continues in background...")
            else:
                raise
    except Exception as e:
        print(f"[X] Failed to load script: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.exit(1)

    print(f"[*] Hunting (up to {MAX_WAIT_SECONDS}s)...")
    for i in range(MAX_WAIT_SECONDS):
        time.sleep(1)
        if done or script_error:
            break
        if (i + 1) % 30 == 0:
            print(f"\n[*] Still running... {i + 1}s elapsed")

    # ── Show summary from JS side ─────────────────────────────────────
    if done_payload:
        top = done_payload.get("top_regions", [])
        print()
        print("=" * 60)
        print("  REGION SUMMARY (ranked by how many target IDs found)")
        print("=" * 60)
        for r in top[:10]:
            ids = r.get("matchedIds", [])
            print(f"  Region #{r['regionIndex']}: {r['matchedIdCount']}/{len(KNOWN_IDS)} IDs, "
                  f"{r['totalHits']} hits, size={r['rangeSize']}")
            print(f"    IDs found: {ids}")

    if not region_chunks:
        print("\n[X] No matching regions found.")
        if script_error:
            print("    A script error occurred — see above.")
        print("    Try adding more known IDs or checking you're on the right page.")
        sys.exit(1)

    # ── Deserialize and find arrays containing our IDs ─────────────────
    print()
    print("=" * 60)
    print("  SEARCHING RAW BYTES FOR MSGPACK ARRAYS...")
    print("=" * 60)

    best_result = None

    for chunk_idx, (meta, raw) in enumerate(region_chunks):
        region_idx = meta.get("region_index")
        print(f"\n[*] Analyzing region #{region_idx} (chunk {chunk_idx+1}/{len(region_chunks)}, {len(raw):,} bytes)...")

        structures = find_msgpack_structures(raw, KNOWN_IDS)

        if structures:
            for s in structures[:3]:
                print(f"\n  ✅ Found {s['description']} at offset {s['offset']}")
                print(f"     Contains {s['found_count']}/{len(KNOWN_IDS)} known IDs: {s['found_ids']}")

                data = s["data"]
                # Preview
                if isinstance(data, list):
                    for i, item in enumerate(data[:3]):
                        preview = json.dumps(item, ensure_ascii=False, default=str)
                        if len(preview) > 300:
                            preview = preview[:300] + "..."
                        print(f"     [{i}] {preview}")
                    if len(data) > 3:
                        print(f"     ... and {len(data) - 3} more items")
                elif isinstance(data, dict):
                    keys = list(data.keys())[:20]
                    print(f"     Top-level keys: {keys}")
                    # Show a couple values
                    for k in keys[:3]:
                        v = data[k]
                        preview = json.dumps(v, ensure_ascii=False, default=str)
                        if len(preview) > 200:
                            preview = preview[:200] + "..."
                        print(f"     [{k}] = {preview}")

                if not best_result or s["found_count"] > best_result["found_count"]:
                    best_result = s
        else:
            print("  No MsgPack structures found containing target IDs.")
            print("  Dumping raw hex context around ID locations...")
            contexts = dump_raw_context(raw, KNOWN_IDS)
            if contexts:
                for ctx in contexts[:8]:
                    print(f"\n  Raw ID {ctx['id']} at byte offset {ctx['offset']}:")
                    print(f"    HEX:   {ctx['hex_dump']}")
                    print(f"    ASCII: {ctx['ascii']}")
            else:
                print("  IDs not found as raw LE32 either.")

    if not best_result:
        print("\n[X] Could not find a MsgPack structure containing the target IDs.")
        print("    Possible reasons:")
        print("    - The data is in native C#/Unity structs (not MsgPack)")
        print("    - The data uses a different serialization format")
        print("    - Need more known IDs to narrow down the search")
        print("    Check the raw hex dumps above for clues.")
        sys.exit(1)

    # ── Save the best result ───────────────────────────────────────────
    data = best_result["data"]

    # Strip PII
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

    output_file = os.path.abspath("hunted_data.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print()
    print("=" * 60)
    print(f"  SAVED: {output_file}")
    print(f"  Type: {best_result['description']}")
    print(f"  Contains {best_result['found_count']}/{len(KNOWN_IDS)} known IDs")
    print("=" * 60)

    # Print full data if small enough
    item_count = len(data) if isinstance(data, (list, dict)) else 1
    if item_count <= 50:
        print()
        print(json.dumps(data, indent=2, ensure_ascii=False))

    # Print keys from the structure to help identify it
    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        print(f"\n  Keys in each item: {list(data[0].keys())}")
    elif isinstance(data, dict):
        print(f"\n  Top-level keys ({len(data)}): {list(data.keys())[:30]}")
        first_val = next(iter(data.values()), None)
        if isinstance(first_val, dict):
            print(f"  Keys in first value: {list(first_val.keys())}")


if __name__ == "__main__":
    main()

