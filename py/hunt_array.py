# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
"""
Uma Musume Array Hunter v2
============================
Scans game memory for arrays/structures containing specific known IDs.
Uses targeted analysis instead of brute-force byte scanning.

All output is written to both the console AND hunt_debug.log for later review.

Usage:
  python hunt_array.py
"""
import json
import os
import struct
import sys
import time
import traceback
import logging
from collections import defaultdict

import frida
import msgpack

# ── Config ─────────────────────────────────────────────────────────────────

TARGET_PROCESS_NAMES = [
    "UmamusumePrettyDerby.exe",
    "UmamusumePrettyDerby",
]
PROCESS_KEYWORDS = ["uma", "musume", "derby", "cygames"]
MAX_WAIT_SECONDS = 30000

KNOWN_IDS = [200154, 200152, 200441, 200652, 200722, 201152]

# ── Debug log setup ────────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(_SCRIPT_DIR, "hunt_debug.log")

logger = logging.getLogger("hunt")
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


# ── Frida JS script ───────────────────────────────────────────────────────

def build_hunt_script(known_ids):
    ids_json = json.dumps(known_ids)
    return r"""
console.log("=== Uma Musume Array Hunter v2 ===");
console.log("Searching for arrays containing known IDs...");

(function() {
    const knownIds = """ + ids_json + r""";
    const scanProtection = "rw-";
    const minRangeSize = 16 * 1024;
    const maxRangeSize = 500 * 1024 * 1024;

    function intToMsgPackPatterns(val) {
        const patterns = [];
        if (val >= 0 && val <= 0xFFFFFFFF) {
            const b3 = (val >>> 24) & 0xFF, b2 = (val >>> 16) & 0xFF;
            const b1 = (val >>> 8) & 0xFF,  b0 = val & 0xFF;
            patterns.push({ label: `msgpack_uint32(${val})`, hex: `CE ${hex(b3)} ${hex(b2)} ${hex(b1)} ${hex(b0)}`, size: 5 });
        }
        if (val >= 0 && val <= 0xFFFF) {
            patterns.push({ label: `msgpack_uint16(${val})`, hex: `CD ${hex((val>>>8)&0xFF)} ${hex(val&0xFF)}`, size: 3 });
        }
        if (val >= 0 && val <= 0xFF) {
            patterns.push({ label: `msgpack_uint8(${val})`, hex: `CC ${hex(val)}`, size: 2 });
        }
        if (val >= 0 && val <= 127) {
            patterns.push({ label: `msgpack_fixint(${val})`, hex: hex(val), size: 1 });
        }
        if (val >= -2147483648 && val <= 2147483647) {
            const v = val < 0 ? val + 0x100000000 : val;
            const b3 = (v >>> 24) & 0xFF, b2 = (v >>> 16) & 0xFF;
            const b1 = (v >>> 8) & 0xFF,  b0 = v & 0xFF;
            patterns.push({ label: `msgpack_int32(${val})`, hex: `D2 ${hex(b3)} ${hex(b2)} ${hex(b1)} ${hex(b0)}`, size: 5 });
        }
        if (val >= 0 && val <= 0xFFFFFFFF) {
            const b0 = val & 0xFF, b1 = (val >>> 8) & 0xFF;
            const b2 = (val >>> 16) & 0xFF, b3 = (val >>> 24) & 0xFF;
            patterns.push({ label: `raw_le32(${val})`, hex: `${hex(b0)} ${hex(b1)} ${hex(b2)} ${hex(b3)}`, size: 4 });
        }
        return patterns;
    }

    function hex(b) { return ('0' + b.toString(16).toUpperCase()).slice(-2); }

    const rawRanges = Process.enumerateRanges({protection: scanProtection, coalesce: true});
    const ranges = [];
    for (const r of rawRanges) {
        if (r.size >= minRangeSize && r.size <= maxRangeSize) ranges.push(r);
    }
    ranges.sort((a, b) => b.size - a.size);
    console.log(`${ranges.length} scannable regions (from ${rawRanges.length} total)`);

    const regionHits = {};
    let totalScans = 0;
    const allPatterns = [];
    for (const id of knownIds) {
        for (const p of intToMsgPackPatterns(id)) allPatterns.push({ id, ...p });
    }
    const totalWork = allPatterns.length * ranges.length;
    console.log(`Scanning ${allPatterns.length} patterns x ${ranges.length} regions = ${totalWork} scans...`);
    send({ type: 'status', message: `Hunting for ${knownIds.length} IDs across ${ranges.length} regions...` });

    for (const pat of allPatterns) {
        for (let ri = 0; ri < ranges.length; ri++) {
            totalScans++;
            if (totalScans % 500 === 0) {
                send({ type: 'progress', pct: Math.round(totalScans / totalWork * 100), scanned: totalScans, total: totalWork });
            }
            const range = ranges[ri];
            try {
                const results = Memory.scanSync(range.base, range.size, pat.hex);
                if (results.length > 0) {
                    if (!regionHits[ri]) regionHits[ri] = { ids: new Set(), addresses: [], rangeBase: range.base, rangeSize: range.size };
                    regionHits[ri].ids.add(pat.id);
                    for (const r of results) {
                        regionHits[ri].addresses.push({ id: pat.id, address: r.address, encoding: pat.label, encodingSize: pat.size });
                    }
                }
            } catch(e) { continue; }
        }
    }

    const regionScores = Object.entries(regionHits)
        .map(([ri, info]) => ({
            regionIndex: parseInt(ri), matchedIdCount: info.ids.size, matchedIds: Array.from(info.ids),
            totalHits: info.addresses.length, rangeBase: info.rangeBase, rangeSize: info.rangeSize, addresses: info.addresses
        }))
        .sort((a, b) => b.matchedIdCount - a.matchedIdCount || b.totalHits - a.totalHits);

    console.log(`\nRESULTS: ${regionScores.length} regions contain at least one target ID\n`);
    for (const region of regionScores.slice(0, 10)) {
        console.log(`Region #${region.regionIndex}: ${region.matchedIdCount}/${knownIds.length} IDs, ${region.totalHits} hits, size=${region.rangeSize}`);
        for (const addr of region.addresses.slice(0, 20))
            console.log(`  ID ${addr.id} (${addr.encoding}) at ${addr.address}`);
    }

    let bestRegions = regionScores.filter(r => r.matchedIdCount === knownIds.length).slice(0, 5);
    if (bestRegions.length === 0) {
        const fallback = regionScores.filter(r => r.matchedIdCount >= Math.max(2, knownIds.length - 1)).slice(0, 5);
        if (fallback.length > 0) { console.log(`Falling back to best partial matches...`); bestRegions = fallback; }
        else if (regionScores.length > 0) { console.log(`Sending best available...`); bestRegions = regionScores.slice(0, 3); }
    }

    for (const region of bestRegions) {
        let minAddr = region.addresses[0].address, maxAddr = region.addresses[0].address;
        for (const a of region.addresses) {
            if (a.address.compare(minAddr) < 0) minAddr = a.address;
            if (a.address.compare(maxAddr) > 0) maxAddr = a.address;
        }
        const readBefore = 64 * 1024, readAfter = 2 * 1024 * 1024;
        const readStart = minAddr.sub(readBefore);
        const clampedStart = readStart.compare(region.rangeBase) < 0 ? region.rangeBase : readStart;
        const span = maxAddr.sub(clampedStart).toInt32() + readAfter;
        const maxRead = Math.min(span, region.rangeSize - clampedStart.sub(region.rangeBase).toInt32(), 25 * 1024 * 1024);
        if (maxRead <= 0) continue;
        try {
            const data = clampedStart.readByteArray(maxRead);
            console.log(`\nSending ${maxRead} bytes from region #${region.regionIndex}`);
            const hitOffsets = region.addresses.map(a => ({
                id: a.id, encoding: a.encoding, encodingSize: a.encodingSize,
                byteOffset: a.address.sub(clampedStart).toInt32()
            })).filter(h => h.byteOffset >= 0 && h.byteOffset < maxRead);
            send({
                type: 'region_data', region_index: region.regionIndex,
                matched_id_count: region.matchedIdCount, matched_ids: region.matchedIds,
                total_hits: region.totalHits, range_size: region.rangeSize,
                read_size: maxRead, read_base: clampedStart.toString(), hit_offsets: hitOffsets
            }, data);
        } catch(e) { console.log(`Failed to read region #${region.regionIndex}: ${e}`); }
    }

    send({
        type: 'done', regions_with_hits: regionScores.length,
        top_regions: regionScores.slice(0, 20).map(r => ({
            regionIndex: r.regionIndex, matchedIdCount: r.matchedIdCount,
            matchedIds: r.matchedIds, totalHits: r.totalHits, rangeSize: r.rangeSize
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


# ── Smart analysis functions ───────────────────────────────────────────────

def deep_find_ids(obj, known_set, found=None, depth=0):
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


def try_msgpack_at(raw_bytes, offset, known_set, max_read=10 * 1024 * 1024):
    if offset < 0 or offset >= len(raw_bytes):
        return None
    chunk = raw_bytes[offset:min(offset + max_read, len(raw_bytes))]
    try:
        unpacker = msgpack.Unpacker(raw=False, max_buffer_size=50 * 1024 * 1024)
        unpacker.feed(chunk)
        decoded = unpacker.unpack()
        if decoded is None:
            return None
        if isinstance(decoded, (list, dict)) and len(decoded) == 0:
            return None
        consumed = unpacker.tell()
        found_ids = deep_find_ids(decoded, known_set)
        return {
            "offset": offset,
            "decoded": decoded,
            "consumed": consumed,
            "found_ids": found_ids,
        }
    except Exception:
        return None


def targeted_msgpack_search(raw_bytes, hit_offsets, known_ids):
    known_set = set(known_ids)
    results = []
    seen_offsets = set()

    msgpack_hits = [h for h in hit_offsets if "msgpack" in h["encoding"]]
    sorted_hits = sorted(msgpack_hits, key=lambda h: h["byteOffset"])

    if not sorted_hits:
        log("    No MsgPack-encoded hits to search backwards from")
        return results

    log(f"    Targeted MsgPack search from {len(sorted_hits)} hit locations...")
    log_debug(f"    MsgPack hit offsets: {[h['byteOffset'] for h in sorted_hits[:20]]}")

    for hit in sorted_hits:
        offset = hit["byteOffset"]
        max_back = 256 * 1024
        start_search = max(0, offset - max_back)
        containers_checked = 0

        for back_offset in range(offset - 1, start_search - 1, -1):
            if back_offset in seen_offsets:
                continue
            if back_offset < 0:
                break

            b = raw_bytes[back_offset]

            is_container = False
            if 0x92 <= b <= 0x9F:
                is_container = True
            elif b in (0xDC, 0xDD):
                is_container = True
            elif 0x82 <= b <= 0x8F:
                is_container = True
            elif b in (0xDE, 0xDF):
                is_container = True

            if not is_container:
                continue

            seen_offsets.add(back_offset)
            containers_checked += 1
            result = try_msgpack_at(raw_bytes, back_offset, known_set)
            if result is None:
                continue

            found_count = len(result["found_ids"])
            if found_count < 2:
                continue

            decoded = result["decoded"]
            if isinstance(decoded, list):
                desc = f"array[{len(decoded)}]"
            elif isinstance(decoded, dict):
                desc = f"map[{len(decoded)} keys]"
            else:
                desc = type(decoded).__name__

            log(f"    HIT: MsgPack {desc} at offset {back_offset} "
                f"({found_count}/{len(known_ids)} IDs, consumed {result['consumed']} bytes)")
            log_debug(f"    Found IDs: {sorted(result['found_ids'])}")
            results.append({
                "offset": back_offset,
                "description": desc,
                "found_ids": sorted(result["found_ids"]),
                "found_count": found_count,
                "data": decoded,
                "consumed": result["consumed"],
                "source": "targeted_backward_search",
            })

            if found_count == len(known_ids):
                break

        log_debug(f"    Hit at {offset}: checked {containers_checked} container headers backwards")

    # Deduplicate by offset
    unique = {}
    for r in results:
        off = r["offset"]
        if off not in unique or r["found_count"] > unique[off]["found_count"]:
            unique[off] = r
    results = sorted(unique.values(), key=lambda r: r["found_count"], reverse=True)
    return results


def analyze_raw_layout(raw_bytes, hit_offsets, known_ids):
    by_encoding = defaultdict(list)
    for h in hit_offsets:
        enc_type = "msgpack" if "msgpack" in h["encoding"] else "raw_le32"
        by_encoding[enc_type].append(h)

    log(f"    Hit breakdown: {len(by_encoding.get('msgpack', []))} MsgPack, "
        f"{len(by_encoding.get('raw_le32', []))} raw LE32")

    raw_hits = by_encoding.get("raw_le32", [])
    if not raw_hits:
        raw_hits = hit_offsets

    if not raw_hits:
        log("    No hits to analyze")
        return []

    id_locations = defaultdict(list)
    for h in raw_hits:
        id_locations[h["id"]].append(h["byteOffset"])

    log("\n    Per-ID raw locations:")
    for id_val in known_ids:
        locs = sorted(id_locations.get(id_val, []))
        if locs:
            log(f"      ID {id_val}: {len(locs)} occurrences at offsets {locs[:10]}{'...' if len(locs) > 10 else ''}")
            log_debug(f"      ID {id_val}: ALL offsets = {locs}")
        else:
            log(f"      ID {id_val}: not found as raw LE32")

    # Spacing analysis
    log("\n    Spacing analysis (looking for regular struct patterns):")
    struct_size_candidates = defaultdict(int)

    for id_val, locs in id_locations.items():
        if len(locs) < 2:
            continue
        sorted_locs = sorted(locs)
        spacings = [sorted_locs[i + 1] - sorted_locs[i] for i in range(len(sorted_locs) - 1)]

        spacing_freq = defaultdict(int)
        for s in spacings:
            if 8 <= s <= 4096:
                spacing_freq[s] += 1

        if spacing_freq:
            most_common = sorted(spacing_freq.items(), key=lambda x: -x[1])[:3]
            log(f"      ID {id_val}: spacings = {most_common}")
            log_debug(f"      ID {id_val}: all spacings = {spacings}")
            for spacing, count in most_common:
                if count >= 2:
                    struct_size_candidates[spacing] += count

    if struct_size_candidates:
        best_sizes = sorted(struct_size_candidates.items(), key=lambda x: -x[1])[:5]
        log(f"\n    Most likely struct sizes: {best_sizes}")
    else:
        log("    No regular spacing detected (data may not be a struct array)")

    # Cross-ID proximity analysis
    log("\n    Cross-ID proximity (IDs that appear near each other):")
    all_hits_sorted = sorted(raw_hits, key=lambda h: h["byteOffset"])

    clusters = []
    current_cluster = [all_hits_sorted[0]] if all_hits_sorted else []

    for i in range(1, len(all_hits_sorted)):
        h = all_hits_sorted[i]
        prev = all_hits_sorted[i - 1]
        if h["byteOffset"] - prev["byteOffset"] <= 4096:
            current_cluster.append(h)
        else:
            if len(current_cluster) >= 2:
                clusters.append(current_cluster)
            current_cluster = [h]

    if len(current_cluster) >= 2:
        clusters.append(current_cluster)

    multi_id_clusters = [c for c in clusters if len(set(h["id"] for h in c)) >= 2]
    log(f"    Found {len(multi_id_clusters)} clusters with 2+ different IDs nearby:")

    for ci, cluster in enumerate(multi_id_clusters[:5]):
        cluster_ids = set(h["id"] for h in cluster)
        min_off = min(h["byteOffset"] for h in cluster)
        max_off = max(h["byteOffset"] for h in cluster)
        log(f"      Cluster {ci}: offsets {min_off}-{max_off} ({max_off - min_off} bytes span), "
            f"IDs: {sorted(cluster_ids)}")
        log_debug(f"      Cluster {ci} detail: {[(h['id'], h['byteOffset'], h['encoding']) for h in cluster]}")

    return multi_id_clusters


def dump_hex_context(raw_bytes, hit_offsets, known_ids, context_bytes=128):
    log(f"\n    Hex context around each hit (+/-{context_bytes} bytes):")

    seen = set()
    unique_hits = []
    for h in sorted(hit_offsets, key=lambda x: x["byteOffset"]):
        key = (h["id"], h["byteOffset"])
        if key not in seen:
            seen.add(key)
            unique_hits.append(h)

    for h in unique_hits[:20]:
        offset = h["byteOffset"]
        id_val = h["id"]
        encoding = h["encoding"]
        enc_size = h.get("encodingSize", 4)

        start = max(0, offset - context_bytes)
        end = min(len(raw_bytes), offset + context_bytes)
        snippet = raw_bytes[start:end]

        hex_lines = []
        ascii_lines = []
        line_size = 32
        for row_start in range(0, len(snippet), line_size):
            row = snippet[row_start:row_start + line_size]
            abs_offset = start + row_start

            hex_parts = []
            ascii_parts = []
            for bi, b in enumerate(row):
                abs_pos = abs_offset + bi
                if abs_pos == offset:
                    hex_parts.append(f"[{b:02X}")
                elif abs_pos == offset + enc_size - 1:
                    hex_parts.append(f"{b:02X}]")
                else:
                    hex_parts.append(f"{b:02X}")
                ascii_parts.append(chr(b) if 32 <= b < 127 else ".")

            hex_lines.append(f"      {abs_offset:08X}: {' '.join(hex_parts)}")
            ascii_lines.append("".join(ascii_parts))

        log(f"\n    -- ID {id_val} ({encoding}) at offset {offset} --")
        for hl, al in zip(hex_lines, ascii_lines):
            log(f"{hl}  |{al}|")


def find_nearby_strings(raw_bytes, offset, search_range=512):
    start = max(0, offset - search_range)
    end = min(len(raw_bytes), offset + search_range)
    chunk = raw_bytes[start:end]

    strings = []
    current = []
    current_start = 0

    for i, b in enumerate(chunk):
        if 32 <= b < 127:
            if not current:
                current_start = i
            current.append(chr(b))
        else:
            if len(current) >= 4:
                strings.append({
                    "text": "".join(current),
                    "offset": start + current_start,
                    "rel_offset": (start + current_start) - offset,
                })
            current = []
    if len(current) >= 4:
        strings.append({
            "text": "".join(current),
            "offset": start + current_start,
            "rel_offset": (start + current_start) - offset,
        })
    return strings


def try_extract_structs(raw_bytes, hit_offsets, known_ids, struct_size):
    anchor = None
    for h in hit_offsets:
        if "raw_le32" in h["encoding"]:
            anchor = h
            break
    if not anchor:
        return None

    anchor_off = anchor["byteOffset"]

    test_off = anchor_off
    while test_off - struct_size >= 0:
        prev_off = test_off - struct_size
        if prev_off < 0:
            break
        chunk = raw_bytes[prev_off:prev_off + min(struct_size, 32)]
        if len(chunk) < 8:
            break
        if all(b == 0 for b in chunk) or all(b == 0xFF for b in chunk):
            break
        test_off = prev_off

    array_start = test_off

    test_off = anchor_off + struct_size
    while test_off + struct_size <= len(raw_bytes):
        chunk = raw_bytes[test_off:test_off + min(struct_size, 32)]
        if len(chunk) < 8:
            break
        if all(b == 0 for b in chunk) or all(b == 0xFF for b in chunk):
            break
        test_off += struct_size

    array_end = test_off
    item_count = (array_end - array_start) // struct_size

    log(f"\n    Struct array extraction (struct_size={struct_size}):")
    log(f"      Range: offset {array_start} - {array_end} ({item_count} items)")

    items = []
    for i in range(min(item_count, 200)):
        off = array_start + i * struct_size
        item_bytes = raw_bytes[off:off + struct_size]
        fields = []
        for fi in range(0, len(item_bytes) - 3, 4):
            val = struct.unpack_from("<I", item_bytes, fi)[0]
            fields.append(val)
        items.append({
            "offset": off,
            "fields_u32": fields,
            "raw": item_bytes.hex(),
        })

    return {
        "struct_size": struct_size,
        "array_start": array_start,
        "array_end": array_end,
        "item_count": item_count,
        "items": items,
    }


def analyze_region(raw_bytes, meta, known_ids):
    hit_offsets = meta.get("hit_offsets", [])
    region_idx = meta.get("region_index")
    known_set = set(known_ids)

    if not hit_offsets:
        log(f"  [!] No hit offsets received for region #{region_idx}")
        log("      Falling back to raw ID search in bytes...")
        for id_val in known_ids:
            target = struct.pack("<I", id_val)
            pos = 0
            while True:
                idx = raw_bytes.find(target, pos)
                if idx == -1:
                    break
                hit_offsets.append({
                    "id": id_val,
                    "encoding": f"raw_le32({id_val})",
                    "encodingSize": 4,
                    "byteOffset": idx,
                })
                pos = idx + 4

    log(f"  Working with {len(hit_offsets)} hit locations in {len(raw_bytes):,} bytes")
    log_debug(f"  All hit encodings: {[(h['id'], h['encoding'], h['byteOffset']) for h in hit_offsets[:50]]}")

    best_result = None

    # Strategy 1: Targeted MsgPack backward search
    log("\n  > Strategy 1: Targeted MsgPack search (backward from hits)...")
    msgpack_results = targeted_msgpack_search(raw_bytes, hit_offsets, known_ids)
    if msgpack_results:
        for r in msgpack_results[:3]:
            log(f"    Found {r['description']} with {r['found_count']}/{len(known_ids)} IDs")
        best = msgpack_results[0]
        if best["found_count"] >= len(known_ids):
            log("    Perfect MsgPack match found!")
            best_result = best
    else:
        log("    No MsgPack containers found enclosing the target IDs")

    # Strategy 2: Raw struct layout analysis
    log("\n  > Strategy 2: Raw struct layout analysis...")
    multi_id_clusters = analyze_raw_layout(raw_bytes, hit_offsets, known_ids)

    # Strategy 3: Try MsgPack at various offsets before clusters
    if not best_result and multi_id_clusters:
        log("\n  > Strategy 3: MsgPack probe from cluster starts...")
        for ci, cluster in enumerate(multi_id_clusters[:3]):
            min_off = min(h["byteOffset"] for h in cluster)
            for probe_back in [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512,
                               1024, 2048, 4096, 8192, 16384, 32768, 65536]:
                probe_off = max(0, min_off - probe_back)
                result = try_msgpack_at(raw_bytes, probe_off, known_set)
                if result and len(result["found_ids"]) >= 2:
                    decoded = result["decoded"]
                    if isinstance(decoded, list):
                        desc = f"array[{len(decoded)}]"
                    elif isinstance(decoded, dict):
                        desc = f"map[{len(decoded)} keys]"
                    else:
                        desc = type(decoded).__name__
                    found_count = len(result["found_ids"])
                    log(f"    MsgPack {desc} at offset {probe_off} "
                        f"({found_count}/{len(known_ids)} IDs)")
                    log_debug(f"    Probe found IDs: {sorted(result['found_ids'])}")
                    if not best_result or found_count > best_result.get("found_count", 0):
                        best_result = {
                            "offset": probe_off,
                            "description": desc,
                            "found_ids": sorted(result["found_ids"]),
                            "found_count": found_count,
                            "data": decoded,
                            "consumed": result["consumed"],
                            "source": "cluster_probe",
                        }
                    if found_count == len(known_ids):
                        break

    # Strategy 4: Nearby strings analysis
    log("\n  > Strategy 4: Nearby strings analysis...")
    all_nearby_strings = set()
    for h in hit_offsets[:12]:
        strings = find_nearby_strings(raw_bytes, h["byteOffset"], search_range=256)
        for s in strings:
            if len(s["text"]) >= 4:
                all_nearby_strings.add(s["text"])

    if all_nearby_strings:
        interesting = [s for s in all_nearby_strings
                       if not all(c in "0123456789" for c in s)
                       and len(s) <= 100]
        interesting.sort()
        log(f"    Found {len(interesting)} unique strings near ID locations:")
        for s in interesting[:30]:
            log(f'      "{s}"')
        log_debug(f"    ALL nearby strings: {interesting}")
    else:
        log("    No readable strings found near ID locations")

    # Hex dumps
    dump_hex_context(raw_bytes, hit_offsets, known_ids, context_bytes=64)

    return best_result


# ── Main ───────────────────────────────────────────────────────────────────

PII_FIELDS = ["viewer_id", "owner_viewer_id", "dmm_viewer_id"]


def main():
    log("=" * 60)
    log("  Uma Musume Array Hunter v2")
    log(f"  Looking for arrays containing: {KNOWN_IDS}")
    log(f"  Debug log: {LOG_FILE}")
    log("=" * 60)
    log()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    region_chunks = []
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
                    log(f"\n[OK] Received {len(data):,} bytes from region #{payload.get('region_index')}")
                    log(f"     Matched {payload.get('matched_id_count')}/{len(KNOWN_IDS)} IDs: {payload.get('matched_ids')}")
                    hit_offsets = payload.get("hit_offsets", [])
                    by_enc = defaultdict(int)
                    for h in hit_offsets:
                        enc_type = "msgpack" if "msgpack" in h["encoding"] else "raw_le32"
                        by_enc[enc_type] += 1
                    log(f"     Hit offsets: {len(hit_offsets)} ({dict(by_enc)})")
                    log_debug(f"     All hit offsets: {hit_offsets[:30]}")
                    region_chunks.append((payload, data))

                elif ptype == "progress":
                    pct = payload.get("pct", 0)
                    print(f"[*] Hunting... {pct}%", end="\r")
                    log_debug(f"Progress: {pct}%")

                elif ptype == "status":
                    log(f"[*] {payload.get('message', '')}")

                elif ptype == "done":
                    done = True
                    done_payload = payload
                    log_debug(f"Done payload: {json.dumps(payload, indent=2)}")
                    print()

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

    hunt_script = build_hunt_script(KNOWN_IDS)
    log_debug(f"Generated JS script length: {len(hunt_script)} chars")

    try:
        script = session.create_script(hunt_script, runtime="v8")
        script.on("message", on_message)
        log("[*] Loading hunter script...")
        try:
            script.load()
        except Exception as e:
            if "timeout" in str(e).lower():
                log("[*] Script load timed out, hunt continues in background...")
            else:
                raise
    except Exception as e:
        log(f"[X] Failed to load script: {type(e).__name__}: {e}")
        traceback.print_exc()
        logger.debug(traceback.format_exc())
        sys.exit(1)

    log(f"[*] Hunting (up to {MAX_WAIT_SECONDS}s)...")
    for i in range(MAX_WAIT_SECONDS):
        time.sleep(1)
        if done or script_error:
            break
        if (i + 1) % 30 == 0:
            log(f"\n[*] Still running... {i + 1}s elapsed")

    # Show summary from JS side
    if done_payload:
        top = done_payload.get("top_regions", [])
        log()
        log("=" * 60)
        log("  REGION SUMMARY (ranked by how many target IDs found)")
        log("=" * 60)
        for r in top[:10]:
            ids = r.get("matchedIds", [])
            log(f"  Region #{r['regionIndex']}: {r['matchedIdCount']}/{len(KNOWN_IDS)} IDs, "
                f"{r['totalHits']} hits, size={r['rangeSize']}")
            log(f"    IDs found: {ids}")

    if not region_chunks:
        log("\n[X] No matching regions found.")
        if script_error:
            log("    A script error occurred - see above.")
        log("    Try adding more known IDs or checking you're on the right page.")
        sys.exit(1)

    # Analyze each region
    log()
    log("=" * 60)
    log("  ANALYZING REGIONS (targeted search, no brute-force)")
    log("=" * 60)

    best_result = None

    for chunk_idx, (meta, raw) in enumerate(region_chunks):
        region_idx = meta.get("region_index")
        log(f"\n{'=' * 60}")
        log(f"  Region #{region_idx} (chunk {chunk_idx + 1}/{len(region_chunks)}, {len(raw):,} bytes)")
        log(f"{'=' * 60}")

        result = analyze_region(raw, meta, KNOWN_IDS)

        if result and (not best_result or result.get("found_count", 0) > best_result.get("found_count", 0)):
            best_result = result

    if not best_result:
        log()
        log("=" * 60)
        log("  NO MSGPACK STRUCTURE FOUND")
        log("=" * 60)
        log()
        log("  The target IDs were found in memory but NOT inside MsgPack containers.")
        log("  This likely means the data is stored as:")
        log("    - Native C# objects on Unity's managed heap")
        log("    - A different serialization format (protobuf, flatbuffers, etc.)")
        log()
        log("  Next steps:")
        log("    1. Check hunt_debug.log for full hex dumps and nearby strings")
        log("    2. If you see regular struct spacing, try struct extraction")
        log("    3. Consider hooking the game's API response handler with Frida")

        # Save raw analysis data
        analysis_file = os.path.join(_SCRIPT_DIR, "hunt_analysis.json")
        analysis = {
            "known_ids": KNOWN_IDS,
            "regions_analyzed": len(region_chunks),
            "region_summaries": [],
        }
        for meta, raw in region_chunks:
            hit_offsets = meta.get("hit_offsets", [])
            summary = {
                "region_index": meta.get("region_index"),
                "matched_ids": meta.get("matched_ids"),
                "matched_id_count": meta.get("matched_id_count"),
                "read_size": len(raw),
                "hit_count": len(hit_offsets),
                "hits_by_encoding": {},
            }
            for h in hit_offsets:
                enc = h["encoding"]
                if enc not in summary["hits_by_encoding"]:
                    summary["hits_by_encoding"][enc] = []
                summary["hits_by_encoding"][enc].append(h["byteOffset"])
            analysis["region_summaries"].append(summary)

        with open(analysis_file, "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=2)
        log(f"\n  Analysis saved to: {analysis_file}")
        log(f"  Debug log saved to: {LOG_FILE}")
        sys.exit(1)

    # Save the best result
    data = best_result["data"]

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

    output_file = os.path.join(_SCRIPT_DIR, "hunted_data.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    log()
    log("=" * 60)
    log(f"  SAVED: {output_file}")
    log(f"  Type: {best_result['description']}")
    log(f"  Contains {best_result['found_count']}/{len(KNOWN_IDS)} known IDs")
    log(f"  Debug log: {LOG_FILE}")
    log("=" * 60)

    item_count = len(data) if isinstance(data, (list, dict)) else 1
    if item_count <= 50:
        log()
        log(json.dumps(data, indent=2, ensure_ascii=False))

    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        log(f"\n  Keys in each item: {list(data[0].keys())}")
    elif isinstance(data, dict):
        log(f"\n  Top-level keys ({len(data)}): {list(data.keys())[:30]}")
        first_val = next(iter(data.values()), None)
        if isinstance(first_val, dict):
            log(f"  Keys in first value: {list(first_val.keys())}")


if __name__ == "__main__":
    main()
