# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
"""
Uma Musume Skill Array Extractor
==================================
Finds acquirable skill IDs in game memory by scanning for raw LE32 integers.

The game stores skill data as native IL2CPP objects, NOT MsgPack. This script:
  1. Scans memory for known skill IDs (raw little-endian 32-bit)
  2. Identifies the tightest cluster where multiple known IDs sit nearby
  3. Scans that entire region for ALL uint32 values in the skill ID range
  4. Analyzes struct layout patterns and extracts the full skill list

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
from collections import defaultdict, Counter

import frida

# ── Config ─────────────────────────────────────────────────────────────────

TARGET_PROCESS_NAMES = [
    "UmamusumePrettyDerby.exe",
    "UmamusumePrettyDerby",
]
PROCESS_KEYWORDS = ["uma", "musume", "derby", "cygames"]
MAX_WAIT_SECONDS = 300

# Known skill IDs visible on the acquire screen.
# Only used as anchors to find the right memory region.
# The script will extract ALL skill-range IDs it finds nearby.
KNOWN_SKILL_IDS = [200154, 200152, 200441, 200652, 200722, 201152]

# Integer range that looks like a skill ID
SKILL_ID_MIN = 100000
SKILL_ID_MAX = 999999

# ── Logging ────────────────────────────────────────────────────────────────

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


# ── Frida JS ───────────────────────────────────────────────────────────────

def build_scan_script(known_ids):
    """Scan memory for known skill IDs as raw LE32 and send back regions."""
    ids_json = json.dumps(known_ids)
    return r"""
(function() {
    const knownIds = """ + ids_json + r""";
    const scanProtection = "rw-";
    const minRangeSize = 16 * 1024;
    const maxRangeSize = 500 * 1024 * 1024;

    function hex(b) { return ('0' + b.toString(16).toUpperCase()).slice(-2); }

    // Build raw LE32 patterns for each known ID
    const patterns = [];
    for (const id of knownIds) {
        const b0 = id & 0xFF, b1 = (id >>> 8) & 0xFF;
        const b2 = (id >>> 16) & 0xFF, b3 = (id >>> 24) & 0xFF;
        patterns.push({
            id: id,
            pattern: `${hex(b0)} ${hex(b1)} ${hex(b2)} ${hex(b3)}`,
        });
    }

    const rawRanges = Process.enumerateRanges({protection: scanProtection, coalesce: true});
    const ranges = rawRanges.filter(r => r.size >= minRangeSize && r.size <= maxRangeSize);
    ranges.sort((a, b) => b.size - a.size);

    console.log(`Scanning ${ranges.length} regions for ${patterns.length} skill IDs (raw LE32)...`);
    send({ type: 'status', message: `Scanning ${ranges.length} regions...` });

    // Scan all regions, collect hits by region index
    const regionHits = {};
    let totalScans = 0;
    const totalWork = patterns.length * ranges.length;

    for (const pat of patterns) {
        for (let ri = 0; ri < ranges.length; ri++) {
            totalScans++;
            if (totalScans % 500 === 0) {
                send({ type: 'progress', pct: Math.round(totalScans / totalWork * 100) });
            }
            try {
                const results = Memory.scanSync(ranges[ri].base, ranges[ri].size, pat.pattern);
                if (results.length > 0) {
                    if (!regionHits[ri]) {
                        regionHits[ri] = {
                            ids: new Set(), addresses: [],
                            rangeBase: ranges[ri].base, rangeSize: ranges[ri].size
                        };
                    }
                    regionHits[ri].ids.add(pat.id);
                    for (const r of results) {
                        regionHits[ri].addresses.push({
                            id: pat.id, address: r.address,
                            byteOffset: r.address.sub(ranges[ri].base).toInt32()
                        });
                    }
                }
            } catch(e) { continue; }
        }
    }

    // Rank regions by how many distinct IDs they contain
    const ranked = Object.entries(regionHits)
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

    console.log(`\n${ranked.length} regions contain at least one known ID`);
    for (const r of ranked.slice(0, 5)) {
        console.log(`  Region #${r.regionIndex}: ${r.matchedIdCount}/${knownIds.length} IDs, ` +
            `${r.totalHits} hits, size=${r.rangeSize}`);
    }

    // Send back the top regions (up to 5) with the most ID coverage
    const toSend = ranked.filter(r => r.matchedIdCount >= 2).slice(0, 5);
    if (toSend.length === 0 && ranked.length > 0) {
        toSend.push(ranked[0]);
    }

    for (const region of toSend) {
        // For each region, find the tightest cluster of known IDs
        // and read a generous window around it
        const addrs = region.addresses.sort((a, b) => a.byteOffset - b.byteOffset);
        const minOff = addrs[0].byteOffset;
        const maxOff = addrs[addrs.length - 1].byteOffset;

        // Read: 64KB before first hit, everything through last hit + 64KB after
        const readBefore = 64 * 1024;
        const readAfter = 64 * 1024;
        const readStart = Math.max(0, minOff - readBefore);
        const readEnd = Math.min(region.rangeSize, maxOff + readAfter);
        const readSize = readEnd - readStart;

        if (readSize <= 0 || readSize > 50 * 1024 * 1024) continue;

        try {
            const readBase = region.rangeBase.add(readStart);
            const data = readBase.readByteArray(readSize);

            // Adjust hit offsets relative to what we read
            const adjustedHits = addrs.map(a => ({
                id: a.id,
                byteOffset: a.byteOffset - readStart
            }));

            console.log(`Sending ${readSize} bytes from region #${region.regionIndex} ` +
                `(offsets ${readStart}-${readEnd})`);

            send({
                type: 'region_data',
                region_index: region.regionIndex,
                matched_id_count: region.matchedIdCount,
                matched_ids: region.matchedIds,
                total_hits: region.totalHits,
                range_size: region.rangeSize,
                read_size: readSize,
                read_start: readStart,
                hit_offsets: adjustedHits,
            }, data);
        } catch(e) {
            console.log(`Failed to read region #${region.regionIndex}: ${e}`);
        }
    }

    send({
        type: 'done',
        regions_with_hits: ranked.length,
        top_regions: ranked.slice(0, 15).map(r => ({
            regionIndex: r.regionIndex,
            matchedIdCount: r.matchedIdCount,
            matchedIds: r.matchedIds,
            totalHits: r.totalHits,
            rangeSize: r.rangeSize,
        }))
    });
    console.log("Scan complete.");
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


# ── Analysis ───────────────────────────────────────────────────────────────

def scan_for_skill_range_ids(raw_bytes, align=4):
    """Scan raw bytes for all 4-byte LE uint32 values in the skill ID range.
    Returns list of (offset, value) sorted by offset."""
    hits = []
    end = len(raw_bytes) - 3
    for off in range(0, end, align):
        val = struct.unpack_from("<I", raw_bytes, off)[0]
        if SKILL_ID_MIN <= val <= SKILL_ID_MAX:
            hits.append((off, val))
    return hits


def find_clusters(skill_hits, max_gap=8192):
    """Group skill ID hits into clusters where consecutive hits are within
    max_gap bytes of each other."""
    if not skill_hits:
        return []
    clusters = []
    current = [skill_hits[0]]
    for i in range(1, len(skill_hits)):
        off, val = skill_hits[i]
        prev_off = current[-1][0]
        if off - prev_off <= max_gap:
            current.append(skill_hits[i])
        else:
            clusters.append(current)
            current = [skill_hits[i]]
    clusters.append(current)
    return clusters


def score_cluster(cluster, known_set):
    """Score a cluster by how many known IDs it contains and how dense it is."""
    offsets = [off for off, _ in cluster]
    values = {val for _, val in cluster}
    known_found = values & known_set
    span = max(offsets) - min(offsets) + 4 if len(offsets) > 1 else 4
    density = len(cluster) / max(span, 1)
    return (len(known_found), len(cluster), density)


def analyze_struct_layout(cluster, raw_bytes, known_set):
    """Analyze the byte layout around skill IDs in a cluster to find
    struct patterns."""
    offsets = [off for off, _ in cluster]
    if len(offsets) < 2:
        return None

    # Compute spacings between consecutive skill ID hits
    spacings = []
    for i in range(len(offsets) - 1):
        spacings.append(offsets[i + 1] - offsets[i])

    spacing_counts = Counter(spacings)
    log(f"    Spacing frequency: {spacing_counts.most_common(10)}")

    # The most common spacing likely indicates struct size or field stride
    most_common_spacing, count = spacing_counts.most_common(1)[0]
    log(f"    Most common spacing: {most_common_spacing} bytes ({count} times)")

    # Check if the common spacing is consistent enough to be a struct array
    if count >= max(2, len(offsets) // 3):
        log(f"    → Looks like a struct array with stride {most_common_spacing}")
        return most_common_spacing

    # Try to find a stride that aligns multiple known IDs
    for stride in sorted(spacing_counts.keys()):
        if stride < 8 or stride > 4096:
            continue
        # Check: starting from each known ID offset, do we find other known IDs
        # at multiples of this stride?
        for base_off, base_val in cluster:
            if base_val not in known_set:
                continue
            aligned_count = 0
            for test_off, test_val in cluster:
                if test_val in known_set and (test_off - base_off) % stride == 0:
                    aligned_count += 1
            if aligned_count >= 3:
                log(f"    → Stride {stride} aligns {aligned_count} known IDs")
                return stride

    return None


def extract_skill_ids_simple(cluster, known_set):
    """Simple extraction: just return all unique skill-range IDs found."""
    all_ids = sorted({val for _, val in cluster})
    known_found = sorted(known_set & set(all_ids))
    unknown = sorted(set(all_ids) - known_set)
    return all_ids, known_found, unknown


def extract_skill_ids_strided(cluster, raw_bytes, stride, known_set):
    """Extract skill IDs assuming a struct array with the given stride.
    Finds which field offset within each struct holds the skill ID,
    then reads that field from every struct."""
    offsets = [off for off, _ in cluster]
    values = {off: val for off, val in cluster}

    # Find which byte offset within the stride holds known skill IDs
    known_field_offsets = Counter()
    for off, val in cluster:
        if val in known_set:
            field_off = off % stride
            known_field_offsets[field_off] += 1

    if not known_field_offsets:
        return None

    best_field, _ = known_field_offsets.most_common(1)[0]
    log(f"    Skill ID field is at offset {best_field} within each {stride}-byte struct")

    # Find array bounds
    # Start from earliest known ID, walk backward/forward by stride
    anchor = None
    for off, val in cluster:
        if val in known_set and off % stride == best_field:
            anchor = off
            break
    if anchor is None:
        return None

    # Walk backward
    start = anchor
    while start - stride >= 0:
        prev = start - stride
        val = struct.unpack_from("<I", raw_bytes, prev)[0]
        if SKILL_ID_MIN <= val <= SKILL_ID_MAX:
            start = prev
        else:
            # Check if the struct has other nonzero content (not just the ID field)
            struct_bytes = raw_bytes[prev:prev + stride]
            if all(b == 0 for b in struct_bytes):
                break
            # Check if at least the ID field looks valid
            break

    # Walk forward
    end = anchor
    while end + stride <= len(raw_bytes) - 4:
        nxt = end + stride
        val = struct.unpack_from("<I", raw_bytes, nxt)[0]
        if SKILL_ID_MIN <= val <= SKILL_ID_MAX:
            end = nxt
        else:
            break

    item_count = (end - start) // stride + 1
    log(f"    Array: {item_count} items, offsets {start}–{end}, stride {stride}")

    # Extract the skill ID from each struct
    extracted = []
    for i in range(item_count):
        item_off = start + i * stride
        val = struct.unpack_from("<I", raw_bytes, item_off)[0]
        if SKILL_ID_MIN <= val <= SKILL_ID_MAX:
            extracted.append(val)

    return extracted


def hex_dump_around(raw_bytes, offset, context=64, highlight_len=4):
    """Return hex dump lines around an offset."""
    start = max(0, offset - context)
    end = min(len(raw_bytes), offset + highlight_len + context)
    lines = []
    for row in range(start, end, 16):
        row_bytes = raw_bytes[row:row + 16]
        hex_parts = []
        ascii_parts = []
        for i, b in enumerate(row_bytes):
            pos = row + i
            if offset <= pos < offset + highlight_len:
                hex_parts.append(f"[{b:02X}]")
            else:
                hex_parts.append(f" {b:02X} ")
            ascii_parts.append(chr(b) if 32 <= b < 127 else ".")
        hex_str = "".join(hex_parts)
        ascii_str = "".join(ascii_parts)
        lines.append(f"  {row:08X}: {hex_str}  |{ascii_str}|")
    return lines


def analyze_region(raw_bytes, meta):
    """Main analysis: find all skill IDs, cluster them, extract the array."""
    known_set = set(KNOWN_SKILL_IDS)
    hit_offsets = meta.get("hit_offsets", [])
    region_idx = meta.get("region_index")

    log(f"\n  Region #{region_idx}: {len(raw_bytes):,} bytes, "
        f"{len(hit_offsets)} known-ID hits")

    # Step 1: Verify known IDs are where we expect them
    known_found_here = set()
    for h in hit_offsets:
        off = h["byteOffset"]
        if 0 <= off <= len(raw_bytes) - 4:
            val = struct.unpack_from("<I", raw_bytes, off)[0]
            if val == h["id"]:
                known_found_here.add(val)
            else:
                log_debug(f"    Warning: expected {h['id']} at offset {off}, "
                          f"got {val}")
    log(f"  Verified known IDs: {sorted(known_found_here)}")

    # Step 2: Scan the ENTIRE region for all skill-range uint32s
    log(f"  Scanning {len(raw_bytes):,} bytes for all skill-range integers...")
    all_skill_hits = scan_for_skill_range_ids(raw_bytes, align=4)
    log(f"  Found {len(all_skill_hits)} skill-range integers "
        f"({len(set(v for _, v in all_skill_hits))} unique values)")

    if not all_skill_hits:
        log("  No skill-range integers found!")
        return None

    # Step 3: Cluster the hits
    clusters = find_clusters(all_skill_hits, max_gap=8192)
    log(f"  {len(clusters)} clusters (max gap 8KB)")

    # Score clusters by how many known IDs they contain
    scored = []
    for ci, cluster in enumerate(clusters):
        known_count, total, density = score_cluster(cluster, known_set)
        offsets = [off for off, _ in cluster]
        span = max(offsets) - min(offsets) + 4 if len(offsets) > 1 else 4
        unique_vals = len(set(v for _, v in cluster))
        scored.append((known_count, total, density, ci, cluster,
                        span, unique_vals))
        if known_count > 0 or total >= 5:
            log(f"    Cluster {ci}: {total} hits, {unique_vals} unique IDs, "
                f"span {span} bytes, {known_count}/{len(known_set)} known IDs")

    scored.sort(reverse=True)

    if not scored:
        log("  No clusters found!")
        return None

    # Step 4: Analyze the best cluster
    best = scored[0]
    best_known, best_total, _, best_ci, best_cluster, best_span, best_unique = best
    log(f"\n  ═══ Best cluster: #{best_ci} ═══")
    log(f"  {best_total} skill-range hits, {best_unique} unique values, "
        f"span {best_span} bytes, {best_known}/{len(known_set)} known IDs")

    # Show all values in this cluster
    cluster_values = sorted(set(v for _, v in best_cluster))
    known_in_cluster = sorted(set(cluster_values) & known_set)
    unknown_in_cluster = sorted(set(cluster_values) - known_set)
    log(f"  Known IDs in cluster:   {known_in_cluster}")
    log(f"  Unknown IDs in cluster: {unknown_in_cluster}")

    # Step 5: Analyze struct layout
    log(f"\n  Analyzing struct layout...")
    stride = analyze_struct_layout(best_cluster, raw_bytes, known_set)

    # Step 6: Extract skill IDs
    extracted = None
    if stride:
        log(f"\n  Extracting with stride {stride}...")
        extracted = extract_skill_ids_strided(
            best_cluster, raw_bytes, stride, known_set)
        if extracted:
            log(f"  Extracted {len(extracted)} skill IDs via strided scan")

    # Fallback: simple extraction of all unique IDs in the cluster
    all_ids, known_found, unknown = extract_skill_ids_simple(
        best_cluster, known_set)

    # Step 7: Hex dumps around known IDs for manual inspection
    log(f"\n  Hex context around known IDs:")
    for h in hit_offsets[:6]:
        off = h["byteOffset"]
        log(f"\n    ── ID {h['id']} at offset {off} ──")
        for line in hex_dump_around(raw_bytes, off, context=48):
            log(line)

    # Step 8: Also look at a few unknown IDs for comparison
    unknown_hits = [(off, val) for off, val in best_cluster
                    if val not in known_set]
    if unknown_hits:
        log(f"\n  Hex context around unknown skill-range IDs (first 3):")
        for off, val in unknown_hits[:3]:
            log(f"\n    ── Unknown ID {val} at offset {off} ──")
            for line in hex_dump_around(raw_bytes, off, context=48):
                log(line)

    # Build result
    result = {
        "region_index": region_idx,
        "cluster_index": best_ci,
        "known_ids_found": known_in_cluster,
        "known_id_coverage": f"{len(known_in_cluster)}/{len(known_set)}",
        "all_skill_ids_in_cluster": cluster_values,
        "total_unique_skill_ids": len(cluster_values),
        "cluster_span_bytes": best_span,
        "cluster_hits": best_total,
    }

    if extracted:
        result["extracted_strided"] = extracted
        result["stride"] = stride

    # Also check other high-scoring clusters
    alt_results = []
    for rank, (kc, total, _, ci, cluster, span, uniq) in enumerate(scored[1:5]):
        if kc > 0:
            vals = sorted(set(v for _, v in cluster))
            alt_results.append({
                "cluster_index": ci,
                "known_count": kc,
                "unique_ids": vals,
                "total_hits": total,
                "span": span,
            })
    if alt_results:
        result["alternative_clusters"] = alt_results

    return result


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("  Uma Musume Skill Array Extractor")
    log(f"  Anchor IDs: {KNOWN_SKILL_IDS}")
    log(f"  Scanning for all integers in range {SKILL_ID_MIN}–{SKILL_ID_MAX}")
    log("=" * 60)
    log()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    region_chunks = []
    done = False
    done_payload = None
    script_error = None

    def on_message(message, data):
        nonlocal done, done_payload, script_error

        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                ptype = payload.get("type")

                if ptype == "region_data" and data:
                    log(f"\n  Received {len(data):,} bytes from region "
                        f"#{payload.get('region_index')} "
                        f"({payload.get('matched_id_count')}/{len(KNOWN_SKILL_IDS)} IDs)")
                    region_chunks.append((payload, data))

                elif ptype == "progress":
                    pct = payload.get("pct", 0)
                    print(f"\r  Scanning... {pct}%", end="", flush=True)

                elif ptype == "status":
                    log(f"  {payload.get('message', '')}")

                elif ptype == "done":
                    done = True
                    done_payload = payload
                    print()

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

    scan_js = build_scan_script(KNOWN_SKILL_IDS)
    try:
        script = session.create_script(scan_js, runtime="v8")
        script.on("message", on_message)
        log("[*] Scanning game memory...")
        try:
            script.load()
        except Exception as e:
            if "timeout" in str(e).lower():
                log("[*] Scan still running...")
            else:
                raise
    except Exception as e:
        log(f"[X] Failed: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.exit(1)

    for i in range(MAX_WAIT_SECONDS):
        time.sleep(1)
        if done or script_error:
            break
        if (i + 1) % 30 == 0:
            log(f"\n  Still scanning... {i + 1}s")

    if done_payload:
        top = done_payload.get("top_regions", [])
        if top:
            log()
            log("  Region ranking:")
            for r in top[:8]:
                log(f"    #{r['regionIndex']}: {r['matchedIdCount']}/{len(KNOWN_SKILL_IDS)} IDs, "
                    f"{r['totalHits']} hits, size={r['rangeSize']:,}")

    if not region_chunks:
        log("\n[X] No regions found containing the known skill IDs.")
        sys.exit(1)

    # Analyze each region
    best_result = None
    for chunk_idx, (meta, raw) in enumerate(region_chunks):
        log()
        log("=" * 60)
        result = analyze_region(raw, meta)
        if result:
            known_count = len(result.get("known_ids_found", []))
            if not best_result or known_count > len(best_result.get("known_ids_found", [])):
                best_result = result

    # Final output
    log()
    log("=" * 60)
    log("  RESULTS")
    log("=" * 60)

    if not best_result:
        log("  No skill IDs extracted.")
        log(f"  Check {LOG_FILE} for hex dumps and details.")
        sys.exit(1)

    log(f"  Known ID coverage: {best_result['known_id_coverage']}")
    log(f"  Known IDs found:   {best_result['known_ids_found']}")

    all_ids = best_result["all_skill_ids_in_cluster"]
    log(f"  Total unique skill-range IDs in cluster: {len(all_ids)}")
    log(f"  All IDs: {all_ids}")

    if "extracted_strided" in best_result:
        strided = best_result["extracted_strided"]
        log(f"\n  Strided extraction ({best_result['stride']}-byte stride): "
            f"{len(strided)} IDs")
        log(f"  {strided}")

    # Save output
    output_file = os.path.join(_SCRIPT_DIR, "skill_extraction.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(best_result, f, indent=2)
    log(f"\n  Saved: {output_file}")
    log(f"  Debug: {LOG_FILE}")
    log("=" * 60)


if __name__ == "__main__":
    main()
