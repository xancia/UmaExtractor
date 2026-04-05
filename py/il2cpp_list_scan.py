# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
# ]
# ///
"""
Uma Musume IL2CPP List Scanner
=================================
Scans IL2CPP managed heap for List<T> and T[] objects that contain
integers in the skill-ID range (100000–999999).

Instead of scanning raw memory for bytes, this uses IL2CPP's own
object layout to find ACTUAL managed arrays/lists, then reads their
contents. This avoids false positives from coincidental byte patterns.

Reports every array/list found with its element count and values,
letting YOU decide what each one represents.

Usage:
  python il2cpp_list_scan.py
"""
import json
import os
import sys
import time
import traceback
import logging

import frida

# ── Config ─────────────────────────────────────────────────────────────────

TARGET_PROCESS_NAMES = [
    "UmamusumePrettyDerby.exe",
    "UmamusumePrettyDerby",
]
PROCESS_KEYWORDS = ["uma", "musume", "derby", "cygames"]
MAX_WAIT_SECONDS = 600

# ── Logging ────────────────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(_SCRIPT_DIR, "list_scan.log")
OUTPUT_FILE = os.path.join(_SCRIPT_DIR, "il2cpp_lists.json")

logger = logging.getLogger("listscan")
logger.setLevel(logging.DEBUG)

_fh = logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8")
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_fh)

_ch = logging.StreamHandler(sys.stdout)
_ch.setLevel(logging.WARNING)
_ch.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_ch)


def log(msg="", level="info"):
    getattr(logger, level)(str(msg))


def log_debug(msg=""):
    logger.debug(str(msg))


# ── Frida Script ───────────────────────────────────────────────────────────
# Strategy:
#   IL2CPP arrays (Il2CppArray) have a known layout:
#     +0x00  Il2CppObject header (klass ptr + monitor)
#     +0x08  Il2CppArrayBounds* bounds (usually null for 1D)
#     +0x10  il2cpp_array_size_t max_length
#     +0x14  or +0x18 (depending on pointer size): elements start
#
#   For 64-bit: header=16, bounds=8, max_length=8, data starts at +32
#   For 32-bit: header=8, bounds=4, max_length=4, data starts at +16
#
#   We scan memory for IL2CPP array objects where:
#   - The klass pointer is valid (points to readable memory)
#   - The element type is Int32 or a struct containing Int32
#   - At least some elements are in the skill ID range
#
#   We also look for List<T> objects which wrap arrays:
#     +0x00  Il2CppObject header
#     +0x10  T[] _items  (pointer to backing array)
#     +0x18  int _size   (actual count, may be less than array length)

FRIDA_SCRIPT = r"""
(function() {
    "use strict";

    const ptrSize = Process.pointerSize;
    const is64 = ptrSize === 8;

    // IL2CPP array layout (64-bit):
    //   +0  : klass pointer (8 bytes)
    //   +8  : monitor/sync (8 bytes)
    //   +16 : bounds pointer (8 bytes, usually null for 1D)
    //   +24 : max_length (8 bytes, but only lower 4 used for most arrays)
    //   +32 : elements start
    const ARRAY_HEADER_SIZE = is64 ? 32 : 16;
    const ARRAY_LENGTH_OFFSET = is64 ? 24 : 12;

    // Skill ID range
    const SKILL_MIN = 100000;
    const SKILL_MAX = 999999;

    // ── Resolve IL2CPP APIs ───────────────────────────────────────────

    const GA_NAMES = [
        "GameAssembly.dll", "GameAssembly",
        "libil2cpp.so", "UnityFramework", "GameAssembly.dylib",
    ];

    let gaMod = null;
    for (const name of GA_NAMES) {
        try { gaMod = Process.getModuleByName(name); if (gaMod) break; }
        catch(e) {}
    }

    if (!gaMod) {
        const mods = Process.enumerateModules().map(m => m.name);
        send({ type: "error", message: "GameAssembly not found",
               modules: mods.slice(0, 40) });
        return;
    }

    send({ type: "status", message: `Found ${gaMod.name}` });

    function resolve(name) {
        try {
            if (typeof gaMod.findExportByName === 'function') {
                return gaMod.findExportByName(name) || null;
            }
        } catch(e) {}
        try {
            return Module.findExportByName(gaMod.name, name) || null;
        } catch(e) {}
        try {
            const exports = gaMod.enumerateExports();
            for (const exp of exports) {
                if (exp.name === name) return exp.address;
            }
        } catch(e) {}
        return null;
    }

    const api = {};
    const apiNames = [
        "il2cpp_class_get_name", "il2cpp_class_get_namespace",
        "il2cpp_class_get_element_class", "il2cpp_class_get_type",
        "il2cpp_type_get_type", "il2cpp_class_get_parent",
        "il2cpp_class_get_fields", "il2cpp_field_get_name",
        "il2cpp_field_get_offset", "il2cpp_field_get_type",
        "il2cpp_type_get_name",
    ];
    for (const n of apiNames) {
        api[n] = resolve(n);
    }

    function readCStr(p) {
        if (!p || p.isNull()) return "";
        try { return p.readUtf8String(); } catch(e) { return ""; }
    }

    // Lightweight class-name reader
    const classGetName = api["il2cpp_class_get_name"]
        ? new NativeFunction(api["il2cpp_class_get_name"], "pointer", ["pointer"])
        : null;
    const classGetNs = api["il2cpp_class_get_namespace"]
        ? new NativeFunction(api["il2cpp_class_get_namespace"], "pointer", ["pointer"])
        : null;
    const classGetElem = api["il2cpp_class_get_element_class"]
        ? new NativeFunction(api["il2cpp_class_get_element_class"], "pointer", ["pointer"])
        : null;
    const classGetType = api["il2cpp_class_get_type"]
        ? new NativeFunction(api["il2cpp_class_get_type"], "pointer", ["pointer"])
        : null;
    const typeGetType = api["il2cpp_type_get_type"]
        ? new NativeFunction(api["il2cpp_type_get_type"], "uint32", ["pointer"])
        : null;
    const classGetParent = api["il2cpp_class_get_parent"]
        ? new NativeFunction(api["il2cpp_class_get_parent"], "pointer", ["pointer"])
        : null;
    const classGetFields = api["il2cpp_class_get_fields"]
        ? new NativeFunction(api["il2cpp_class_get_fields"], "pointer", ["pointer", "pointer"])
        : null;
    const fieldGetName = api["il2cpp_field_get_name"]
        ? new NativeFunction(api["il2cpp_field_get_name"], "pointer", ["pointer"])
        : null;
    const fieldGetOffset = api["il2cpp_field_get_offset"]
        ? new NativeFunction(api["il2cpp_field_get_offset"], "int32", ["pointer"])
        : null;
    const fieldGetType = api["il2cpp_field_get_type"]
        ? new NativeFunction(api["il2cpp_field_get_type"], "pointer", ["pointer"])
        : null;
    const typeGetName = api["il2cpp_type_get_name"]
        ? new NativeFunction(api["il2cpp_type_get_name"], "pointer", ["pointer"])
        : null;

    function getClassName(klass) {
        if (!klass || klass.isNull() || !classGetName) return "?";
        try { return readCStr(classGetName(klass)); } catch(e) { return "?"; }
    }

    function getClassNs(klass) {
        if (!klass || klass.isNull() || !classGetNs) return "";
        try { return readCStr(classGetNs(klass)); } catch(e) { return ""; }
    }

    function getFullName(klass) {
        const ns = getClassNs(klass);
        const name = getClassName(klass);
        return ns ? `${ns}.${name}` : name;
    }

    function getClassFieldLayout(klass) {
        if (!classGetFields || !fieldGetName) return [];
        const fields = [];
        try {
            const iter = Memory.alloc(ptrSize);
            iter.writePointer(ptr(0));
            for (let i = 0; i < 100; i++) {
                const f = classGetFields(klass, iter);
                if (f.isNull()) break;
                const name = readCStr(fieldGetName(f));
                const offset = fieldGetOffset ? fieldGetOffset(f) : -1;
                let typeName = "?";
                if (fieldGetType && typeGetName) {
                    try {
                        const ft = fieldGetType(f);
                        typeName = readCStr(typeGetName(ft));
                    } catch(e) {}
                }
                fields.push({ name, type: typeName, offset });
            }
        } catch(e) {}
        return fields;
    }

    // ── Memory scanning approach ──────────────────────────────────────
    //
    // We don't try to walk the GC heap (too fragile across IL2CPP versions).
    // Instead, we scan rw- memory for 4-byte integers in the skill range,
    // and when we find clusters, we check if they look like IL2CPP arrays
    // by examining the preceding bytes for valid klass pointers.

    const scanProt = "rw-";
    const rawRanges = Process.enumerateRanges({protection: scanProt, coalesce: true});
    const ranges = rawRanges.filter(r => r.size >= 64 * 1024 && r.size <= 500 * 1024 * 1024);
    ranges.sort((a, b) => b.size - a.size);

    console.log(`Scanning ${ranges.length} memory regions...`);
    send({ type: "status", message: `Scanning ${ranges.length} rw- regions` });

    // ── Phase 1: Find candidate IL2CPP arrays ─────────────────────────
    //
    // Look for sequences of integers in the skill range that are preceded
    // by what looks like an IL2CPP array header.

    const candidateArrays = [];
    let regionsScanned = 0;

    for (const range of ranges) {
        regionsScanned++;
        if (regionsScanned % 50 === 0) {
            send({ type: "progress", pct: Math.round(regionsScanned / ranges.length * 100) });
        }

        // Quick scan: find any skill-range integer
        // Use Memory.scanSync for the most common prefixes of skill IDs
        // 100000 = 0x000186A0, 999999 = 0x000F423F
        // So bytes 2-3 (big endian) or bytes 0-1 (little endian) vary a lot
        // But byte 2 (LE) is 0x01–0x0F for our range
        // Let's just read regions and scan manually for perf

        let buf;
        try {
            buf = range.base.readByteArray(Math.min(range.size, 50 * 1024 * 1024));
        } catch(e) { continue; }
        if (!buf) continue;

        const view = new DataView(buf);
        const u8 = new Uint8Array(buf);
        const len = buf.byteLength;

        // Scan for skill-range ints at 4-byte alignment
        let i = 0;
        while (i < len - 4) {
            const val = view.getUint32(i, true); // little-endian
            if (val >= SKILL_MIN && val <= SKILL_MAX) {
                // Found a skill-range int. Check if it's part of an array.
                // Walk backward to find the array header.

                // Try several possible element sizes (4 for int, 8/12/16/24 for structs)
                const strides = [4, 8, 12, 16, 20, 24, 28, 32];

                for (const stride of strides) {
                    // Assuming elements are at stride-byte intervals,
                    // count how many consecutive skill-range ints we find
                    let count = 1;
                    let fwd = i + stride;
                    while (fwd < len - 4 && count < 200) {
                        const v = view.getUint32(fwd, true);
                        if (v >= SKILL_MIN && v <= SKILL_MAX) {
                            count++;
                            fwd += stride;
                        } else if (stride > 4) {
                            // For struct arrays, the skill ID might be at a specific
                            // offset within the struct. Try continuing.
                            // But only allow a few misses
                            fwd += stride;
                            // Don't count, but don't break either
                            const nextV = view.getUint32(fwd, true);
                            if (fwd < len - 4 && nextV >= SKILL_MIN && nextV <= SKILL_MAX) {
                                count++;
                                fwd += stride;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }

                    // Also walk backward
                    let bwd = i - stride;
                    let startOff = i;
                    while (bwd >= 0 && count < 200) {
                        const v = view.getUint32(bwd, true);
                        if (v >= SKILL_MIN && v <= SKILL_MAX) {
                            count++;
                            startOff = bwd;
                            bwd -= stride;
                        } else {
                            break;
                        }
                    }

                    if (count >= 5) {
                        // Collect all values
                        const values = [];
                        for (let off = startOff; off < fwd && off < len - 4; off += stride) {
                            const v = view.getUint32(off, true);
                            if (v >= SKILL_MIN && v <= SKILL_MAX) {
                                values.push(v);
                            }
                        }

                        // Check for IL2CPP array header before the data
                        let arrayClassName = null;
                        let arrayLen = -1;
                        const headerOff = startOff - ARRAY_HEADER_SIZE;
                        if (headerOff >= 0 && is64) {
                            try {
                                // Read klass pointer
                                const lo = view.getUint32(headerOff, true);
                                const hi = view.getUint32(headerOff + 4, true);
                                // Check max_length at offset 24
                                const maxLen = view.getUint32(ARRAY_LENGTH_OFFSET + headerOff, true);
                                if (maxLen > 0 && maxLen < 10000) {
                                    arrayLen = maxLen;
                                    // Try to read class name
                                    if (lo !== 0 || hi !== 0) {
                                        const klassPtr = range.base.add(headerOff).readPointer();
                                        if (!klassPtr.isNull()) {
                                            try {
                                                arrayClassName = getFullName(klassPtr);
                                            } catch(e) {}
                                        }
                                    }
                                }
                            } catch(e) {}
                        }

                        // Deduplicate: don't add if we already have an overlapping entry
                        const absStart = range.base.add(startOff);
                        let isDup = false;
                        for (const existing of candidateArrays) {
                            if (existing._rangeBase === range.base.toString() &&
                                Math.abs(existing._startOff - startOff) < stride * 2) {
                                if (values.length > existing.values.length) {
                                    // Replace with better match
                                    existing.values = values;
                                    existing.count = values.length;
                                    existing.stride = stride;
                                    existing.arrayClassName = arrayClassName;
                                    existing.arrayLength = arrayLen;
                                }
                                isDup = true;
                                break;
                            }
                        }

                        if (!isDup) {
                            candidateArrays.push({
                                address: absStart.toString(),
                                _rangeBase: range.base.toString(),
                                _startOff: startOff,
                                stride: stride,
                                count: values.length,
                                uniqueCount: new Set(values).size,
                                values: values,
                                uniqueValues: Array.from(new Set(values)).sort((a,b) => a-b),
                                arrayClassName: arrayClassName,
                                arrayLength: arrayLen,
                            });
                        }
                    }
                }

                // Skip ahead past this cluster
                i += 4;
            } else {
                i += 4;
            }
        }
    }

    console.log(`\nFound ${candidateArrays.length} candidate arrays/sequences`);

    // ── Phase 2: Rank and deduplicate ─────────────────────────────────

    // Remove near-duplicates (overlapping value sets from different strides)
    const seen = new Set();
    const unique = [];
    // Sort by unique count descending
    candidateArrays.sort((a, b) => b.uniqueCount - a.uniqueCount);

    for (const ca of candidateArrays) {
        const key = ca.uniqueValues.join(",");
        if (seen.has(key)) continue;
        // Also check for subsets
        let isSubset = false;
        for (const existing of unique) {
            const existingSet = new Set(existing.uniqueValues);
            if (ca.uniqueValues.every(v => existingSet.has(v))) {
                isSubset = true;
                break;
            }
        }
        if (isSubset) continue;

        seen.add(key);
        unique.push(ca);
    }

    console.log(`${unique.length} unique sequences after dedup`);

    // ── Phase 3: For each candidate, try to identify its IL2CPP type ──

    for (const ca of unique.slice(0, 30)) {
        // Try reading the IL2CPP klass pointer before the data
        if (!ca.arrayClassName && is64) {
            const dataAddr = ptr(ca.address);
            // Try various header positions
            for (const headerSize of [ARRAY_HEADER_SIZE, 16, 24, 40]) {
                try {
                    const klassPtr = dataAddr.sub(headerSize).readPointer();
                    if (!klassPtr.isNull()) {
                        const name = getFullName(klassPtr);
                        if (name && name !== "?" && name.length > 1) {
                            ca.arrayClassName = name;
                            // Also get fields if it's a meaningful class
                            const fields = getClassFieldLayout(klassPtr);
                            if (fields.length > 0) {
                                ca.classFields = fields;
                            }
                            break;
                        }
                    }
                } catch(e) {}
            }
        }

        // Also try to read the klass of the element type
        if (classGetElem && ca.arrayClassName) {
            try {
                const dataAddr = ptr(ca.address);
                const klassPtr = dataAddr.sub(ARRAY_HEADER_SIZE).readPointer();
                if (!klassPtr.isNull()) {
                    const elemClass = classGetElem(klassPtr);
                    if (elemClass && !elemClass.isNull()) {
                        ca.elementType = getFullName(elemClass);
                        const elemFields = getClassFieldLayout(elemClass);
                        if (elemFields.length > 0) {
                            ca.elementFields = elemFields;
                        }
                    }
                }
            } catch(e) {}
        }
    }

    // ── Phase 4: Try reading struct fields for compound element types ──

    for (const ca of unique.slice(0, 20)) {
        if (ca.stride <= 4) continue; // plain int array
        if (!ca.elementFields || ca.elementFields.length === 0) continue;

        // Read first few elements as structs
        const structSamples = [];
        const dataAddr = ptr(ca.address);
        for (let ei = 0; ei < Math.min(ca.count, 5); ei++) {
            const elemAddr = dataAddr.add(ei * ca.stride);
            const sample = {};
            for (const f of ca.elementFields) {
                if (f.offset < 0) continue;
                try {
                    // Read as int32 by default
                    const v = elemAddr.add(f.offset).readS32();
                    sample[f.name] = v;
                } catch(e) {}
            }
            structSamples.push(sample);
        }
        if (structSamples.length > 0) {
            ca.structSamples = structSamples;
        }
    }

    // ── Send results ──────────────────────────────────────────────────

    // Clean up internal fields
    for (const ca of unique) {
        delete ca._rangeBase;
        delete ca._startOff;
    }

    // Log summary
    for (const ca of unique.slice(0, 30)) {
        const type = ca.arrayClassName || "unknown";
        const elem = ca.elementType || "int?";
        console.log(`\n  [${ca.uniqueCount} unique, stride=${ca.stride}] ` +
                     `type=${type} elem=${elem}`);
        console.log(`    values: ${ca.uniqueValues.slice(0, 15).join(", ")}` +
                     (ca.uniqueCount > 15 ? ` ... (${ca.uniqueCount} total)` : ""));
        if (ca.elementFields) {
            console.log(`    element fields: ${ca.elementFields.map(f => f.name).join(", ")}`);
        }
        if (ca.structSamples) {
            console.log(`    sample[0]: ${JSON.stringify(ca.structSamples[0])}`);
        }
    }

    send({
        type: "results",
        total_candidates: candidateArrays.length,
        unique_sequences: unique.length,
        sequences: unique.slice(0, 50),
    });

    console.log("\nDone.");
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


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("  Uma Musume IL2CPP List Scanner")
    log("  Finds arrays/lists containing skill-range integers")
    log("  No assumptions — reports everything it finds")
    log("=" * 60)
    log()
    log("  INSTRUCTIONS:")
    log("  1. Open the game and navigate to the screen with skill data")
    log("     (e.g., trained character detail, skill tree, etc.)")
    log("  2. Wait for the screen to fully load")
    log("  3. Run this script")
    log()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    results = None
    done = False
    error_info = None

    def on_message(message, data):
        nonlocal results, done, error_info

        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                ptype = payload.get("type")

                if ptype == "status":
                    log(f"  {payload.get('message', '')}")

                elif ptype == "progress":
                    pct = payload.get("pct", 0)
                    log_debug(f"  Scanning... {pct}%")

                elif ptype == "results":
                    results = payload
                    done = True

                elif ptype == "error":
                    error_info = payload
                    done = True
                    log(f"  [X] {payload.get('message', '')}")
                    if payload.get("modules"):
                        log(f"  Modules: {payload['modules'][:30]}")

        elif msg_type == "error":
            done = True
            error_info = message
            log(f"  [X] JS Error: {message.get('description', '')}")

        elif msg_type == "log":
            log(f"  [JS] {message.get('payload', '')}")

    try:
        script = session.create_script(FRIDA_SCRIPT, runtime="v8")
        script.on("message", on_message)
        log("[*] Scanning memory for skill-range arrays...")
        print("[*] Running il2cpp_list_scan... see list_scan.log and il2cpp_lists.json for output")
        script.load()
    except Exception as e:
        log(f"[X] Failed: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.exit(1)

    for _ in range(MAX_WAIT_SECONDS):
        time.sleep(0.5)
        if done:
            break

    if error_info:
        log("\n[X] Script failed.")
        sys.exit(1)

    if not results:
        log("\n[X] No results (timeout?).")
        sys.exit(1)

    # ── Display results ────────────────────────────────────────────────

    sequences = results.get("sequences", [])
    log()
    log("=" * 60)
    log("  RESULTS")
    log("=" * 60)
    log(f"  Total candidate sequences: {results.get('total_candidates', 0)}")
    log(f"  Unique sequences:          {results.get('unique_sequences', 0)}")
    log()

    if not sequences:
        log("  No sequences with 5+ skill-range integers found.")
        sys.exit(1)

    # Group by unique count for easier analysis
    for seq in sequences:
        uc = seq.get("uniqueCount", 0)
        stride = seq.get("stride", 0)
        class_name = seq.get("arrayClassName") or "?"
        elem_type = seq.get("elementType") or "?"
        values = seq.get("uniqueValues", [])
        arr_len = seq.get("arrayLength", -1)

        log(f"\n  ── {uc} unique IDs, stride={stride}, "
            f"type={class_name}, elem={elem_type} ──")
        if arr_len >= 0:
            log(f"     IL2CPP array length: {arr_len}")
        if seq.get("elementFields"):
            fields_str = ", ".join(f"{f['name']}:{f['type']}" for f in seq["elementFields"])
            log(f"     Element fields: {fields_str}")
        if seq.get("structSamples"):
            for si, s in enumerate(seq["structSamples"][:3]):
                log(f"     sample[{si}]: {json.dumps(s)}")

        # Print values in rows of 10
        for row_start in range(0, len(values), 10):
            row = values[row_start:row_start + 10]
            log(f"     {', '.join(str(v) for v in row)}")

    # Save full results
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    log(f"\n  Full results: {OUTPUT_FILE}")
    log(f"  Debug log:    {LOG_FILE}")

    # ── Highlight sequences near expected count ────────────────────────

    log()
    log("=" * 60)
    log("  SEQUENCES WITH 15-30 UNIQUE IDs (near expected range)")
    log("=" * 60)

    near_expected = [s for s in sequences
                     if 15 <= s.get("uniqueCount", 0) <= 30]
    if near_expected:
        for seq in near_expected:
            uc = seq["uniqueCount"]
            log(f"\n  ★ {uc} unique IDs, stride={seq['stride']}")
            log(f"    type: {seq.get('arrayClassName', '?')}")
            log(f"    elem: {seq.get('elementType', '?')}")
            log(f"    values: {seq['uniqueValues']}")
            if seq.get("structSamples"):
                log(f"    samples: {seq['structSamples'][:3]}")
    else:
        log("  None found in 15-30 range.")
        log("  Closest matches:")
        by_dist = sorted(sequences,
                         key=lambda s: abs(s.get("uniqueCount", 0) - 23))
        for seq in by_dist[:5]:
            log(f"    {seq['uniqueCount']} unique IDs, stride={seq['stride']}, "
                f"type={seq.get('arrayClassName', '?')}")

    log()
    log("=" * 60)


if __name__ == "__main__":
    main()

