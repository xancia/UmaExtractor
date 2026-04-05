# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
# ]
# ///
"""
Uma Musume IL2CPP Skill Discovery
====================================
Uses IL2CPP runtime introspection to discover ALL skill-related classes,
fields, and methods in the game. No assumptions about what any data means.

This script:
  1. Resolves IL2CPP API functions from GameAssembly.dll
  2. Enumerates all classes, filtering for anything skill-related
  3. Dumps class layouts (fields, methods, parent classes)
  4. Hooks key methods to capture live data flow
  5. Attempts to read live object instances for skill data

Usage:
  python il2cpp_skill_scan.py
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
MAX_WAIT_SECONDS = 300

# Keywords to search for in class/method/field names.
# Case-insensitive. We cast a wide net and filter later.
SEARCH_KEYWORDS = [
    "skill",
    "Skill",
    "acquir",
    "Acquir",
    "learn",
    "Learn",
]

# ── Logging ────────────────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(_SCRIPT_DIR, "il2cpp_scan.log")
OUTPUT_FILE = os.path.join(_SCRIPT_DIR, "il2cpp_skill_classes.json")

logger = logging.getLogger("il2cpp")
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


# ── Frida IL2CPP introspection script ──────────────────────────────────────

FRIDA_SCRIPT = r"""
(function() {
    "use strict";

    // ── Resolve IL2CPP API ────────────────────────────────────────────

    const GA_NAMES = [
        "GameAssembly.dll",
        "GameAssembly",
        "libil2cpp.so",
        "UnityFramework",
        "GameAssembly.dylib",
    ];

    let gaMod = null;
    for (const name of GA_NAMES) {
        try {
            gaMod = Process.getModuleByName(name);
            if (gaMod) break;
        } catch(e) {}
    }

    if (!gaMod) {
        // List all modules for diagnostics
        const mods = Process.enumerateModules().map(m => m.name);
        send({ type: "error", message: "GameAssembly not found",
               all_modules: mods.slice(0, 60) });
        return;
    }

    send({ type: "status",
           message: `Found ${gaMod.name} at ${gaMod.base} (${gaMod.size} bytes)` });

    // Resolve IL2CPP exports
    function resolve(name) {
        try {
            // Try instance method first (newer Frida)
            if (typeof gaMod.findExportByName === 'function') {
                return gaMod.findExportByName(name) || null;
            }
        } catch(e) {}
        try {
            // Fallback to static method (older Frida)
            return Module.findExportByName(gaMod.name, name) || null;
        } catch(e) {}
        try {
            // Last resort: enumerate exports and search
            const exports = gaMod.enumerateExports();
            for (const exp of exports) {
                if (exp.name === name) return exp.address;
            }
        } catch(e) {}
        return null;
    }

    const api = {
        domain_get:              resolve("il2cpp_domain_get"),
        domain_get_assemblies:   resolve("il2cpp_domain_get_assemblies"),
        assembly_get_image:      resolve("il2cpp_assembly_get_image"),
        image_get_class_count:   resolve("il2cpp_image_get_class_count"),
        image_get_class:         resolve("il2cpp_image_get_class"),
        image_get_name:          resolve("il2cpp_image_get_name"),
        class_get_name:          resolve("il2cpp_class_get_name"),
        class_get_namespace:     resolve("il2cpp_class_get_namespace"),
        class_get_parent:        resolve("il2cpp_class_get_parent"),
        class_get_fields:        resolve("il2cpp_class_get_fields"),
        class_get_methods:       resolve("il2cpp_class_get_methods"),
        class_get_type:          resolve("il2cpp_class_get_type"),
        class_get_flags:         resolve("il2cpp_class_get_flags"),
        field_get_name:          resolve("il2cpp_field_get_name"),
        field_get_type:          resolve("il2cpp_field_get_type"),
        field_get_offset:        resolve("il2cpp_field_get_offset"),
        field_get_flags:         resolve("il2cpp_field_get_flags"),
        method_get_name:         resolve("il2cpp_method_get_name"),
        method_get_param_count:  resolve("il2cpp_method_get_param_count"),
        method_get_return_type:  resolve("il2cpp_method_get_return_type"),
        method_get_flags:        resolve("il2cpp_method_get_flags"),
        method_get_param:        resolve("il2cpp_method_get_param"),   // might not exist
        type_get_name:           resolve("il2cpp_type_get_name"),
        type_get_type:           resolve("il2cpp_type_get_type"),
        string_chars:            resolve("il2cpp_string_chars"),
        string_length:           resolve("il2cpp_string_length"),
    };

    // Report which APIs we found
    const resolved = {};
    const missing = [];
    for (const [name, addr] of Object.entries(api)) {
        if (addr) {
            resolved[name] = addr.toString();
        } else {
            missing.push(name);
        }
    }
    send({ type: "api_status",
           resolved_count: Object.keys(resolved).length,
           missing: missing });

    // Check minimum viable API
    const critical = ["domain_get", "domain_get_assemblies", "assembly_get_image",
                      "image_get_class_count", "image_get_class",
                      "class_get_name", "class_get_namespace"];
    for (const name of critical) {
        if (!api[name]) {
            send({ type: "error",
                   message: `Critical API missing: il2cpp_${name}`,
                   resolved: resolved, missing: missing });
            return;
        }
    }

    // ── Create NativeFunctions ────────────────────────────────────────

    const fn = {
        domain_get:            new NativeFunction(api.domain_get,
                                   "pointer", []),
        domain_get_assemblies: new NativeFunction(api.domain_get_assemblies,
                                   "pointer", ["pointer", "pointer"]),
        assembly_get_image:    new NativeFunction(api.assembly_get_image,
                                   "pointer", ["pointer"]),
        image_get_class_count: new NativeFunction(api.image_get_class_count,
                                   "uint32", ["pointer"]),
        image_get_class:       new NativeFunction(api.image_get_class,
                                   "pointer", ["pointer", "uint32"]),
        image_get_name:        new NativeFunction(api.image_get_name,
                                   "pointer", ["pointer"]),
        class_get_name:        new NativeFunction(api.class_get_name,
                                   "pointer", ["pointer"]),
        class_get_namespace:   new NativeFunction(api.class_get_namespace,
                                   "pointer", ["pointer"]),
        class_get_parent:      api.class_get_parent
            ? new NativeFunction(api.class_get_parent, "pointer", ["pointer"])
            : null,
        class_get_fields:      api.class_get_fields
            ? new NativeFunction(api.class_get_fields, "pointer", ["pointer", "pointer"])
            : null,
        class_get_methods:     api.class_get_methods
            ? new NativeFunction(api.class_get_methods, "pointer", ["pointer", "pointer"])
            : null,
        class_get_flags:       api.class_get_flags
            ? new NativeFunction(api.class_get_flags, "uint32", ["pointer"])
            : null,
        field_get_name:        api.field_get_name
            ? new NativeFunction(api.field_get_name, "pointer", ["pointer"])
            : null,
        field_get_type:        api.field_get_type
            ? new NativeFunction(api.field_get_type, "pointer", ["pointer"])
            : null,
        field_get_offset:      api.field_get_offset
            ? new NativeFunction(api.field_get_offset, "int32", ["pointer"])
            : null,
        field_get_flags:       api.field_get_flags
            ? new NativeFunction(api.field_get_flags, "uint32", ["pointer"])
            : null,
        method_get_name:       api.method_get_name
            ? new NativeFunction(api.method_get_name, "pointer", ["pointer"])
            : null,
        method_get_param_count: api.method_get_param_count
            ? new NativeFunction(api.method_get_param_count, "uint32", ["pointer"])
            : null,
        method_get_return_type: api.method_get_return_type
            ? new NativeFunction(api.method_get_return_type, "pointer", ["pointer"])
            : null,
        method_get_flags:      api.method_get_flags
            ? new NativeFunction(api.method_get_flags, "uint32", ["pointer", "pointer"])
            : null,
        type_get_name:         api.type_get_name
            ? new NativeFunction(api.type_get_name, "pointer", ["pointer"])
            : null,
    };

    // ── Helpers ───────────────────────────────────────────────────────

    function readCStr(ptr) {
        if (ptr.isNull()) return "";
        try { return ptr.readUtf8String(); } catch(e) { return ""; }
    }

    function getTypeName(typePtr) {
        if (!typePtr || typePtr.isNull()) return "?";
        if (!fn.type_get_name) return "?";
        try {
            return readCStr(fn.type_get_name(typePtr));
        } catch(e) { return "?"; }
    }

    function getClassName(classPtr) {
        if (!classPtr || classPtr.isNull()) return "";
        return readCStr(fn.class_get_name(classPtr));
    }

    function getClassNamespace(classPtr) {
        if (!classPtr || classPtr.isNull()) return "";
        return readCStr(fn.class_get_namespace(classPtr));
    }

    function getFullClassName(classPtr) {
        const ns = getClassNamespace(classPtr);
        const name = getClassName(classPtr);
        return ns ? `${ns}.${name}` : name;
    }

    // ── Enumerate all assemblies and classes ──────────────────────────

    console.log("=== IL2CPP Skill Discovery ===");

    const domain = fn.domain_get();
    if (domain.isNull()) {
        send({ type: "error", message: "il2cpp_domain_get returned null" });
        return;
    }

    // Get assemblies
    const countBuf = Memory.alloc(4);
    const assembliesPtr = fn.domain_get_assemblies(domain, countBuf);
    const assemblyCount = countBuf.readU32();

    console.log(`Found ${assemblyCount} assemblies`);
    send({ type: "status", message: `Enumerating ${assemblyCount} assemblies...` });

    // Search keywords (lowercase for comparison)
    const keywords = KEYWORDS_PLACEHOLDER;
    const keywordsLower = keywords.map(k => k.toLowerCase());

    function matchesKeyword(name) {
        const lower = name.toLowerCase();
        return keywordsLower.some(kw => lower.includes(kw));
    }

    // ── Scan all classes ──────────────────────────────────────────────

    const matchedClasses = [];
    let totalClasses = 0;
    let totalImages = 0;

    for (let ai = 0; ai < assemblyCount; ai++) {
        const assemblyPtr = assembliesPtr.add(ai * Process.pointerSize).readPointer();
        if (assemblyPtr.isNull()) continue;

        const image = fn.assembly_get_image(assemblyPtr);
        if (image.isNull()) continue;

        const imageName = readCStr(fn.image_get_name(image));
        const classCount = fn.image_get_class_count(image);
        totalImages++;
        totalClasses += classCount;

        for (let ci = 0; ci < classCount; ci++) {
            let classPtr;
            try {
                classPtr = fn.image_get_class(image, ci);
            } catch(e) { continue; }
            if (!classPtr || classPtr.isNull()) continue;

            const className = getClassName(classPtr);
            const ns = getClassNamespace(classPtr);
            const fullName = ns ? `${ns}.${className}` : className;

            // Check if class name matches any keyword
            if (!matchesKeyword(className) && !matchesKeyword(ns)) continue;

            // ── Found a matching class — dump its structure ──────────

            const classInfo = {
                name: className,
                namespace: ns,
                fullName: fullName,
                image: imageName,
                address: classPtr.toString(),
                parent: null,
                fields: [],
                methods: [],
            };

            // Parent class
            if (fn.class_get_parent) {
                try {
                    const parent = fn.class_get_parent(classPtr);
                    if (parent && !parent.isNull()) {
                        classInfo.parent = getFullClassName(parent);
                    }
                } catch(e) {}
            }

            // Fields
            if (fn.class_get_fields && fn.field_get_name) {
                try {
                    const iterBuf = Memory.alloc(Process.pointerSize);
                    iterBuf.writePointer(ptr(0));
                    let fieldCount = 0;
                    while (fieldCount < 200) {
                        const field = fn.class_get_fields(classPtr, iterBuf);
                        if (field.isNull()) break;
                        fieldCount++;

                        const fieldName = readCStr(fn.field_get_name(field));
                        let fieldType = "?";
                        let fieldOffset = -1;
                        let fieldFlags = 0;

                        if (fn.field_get_type) {
                            const ft = fn.field_get_type(field);
                            fieldType = getTypeName(ft);
                        }
                        if (fn.field_get_offset) {
                            fieldOffset = fn.field_get_offset(field);
                        }
                        if (fn.field_get_flags) {
                            fieldFlags = fn.field_get_flags(field);
                        }

                        const isStatic = (fieldFlags & 0x10) !== 0;

                        classInfo.fields.push({
                            name: fieldName,
                            type: fieldType,
                            offset: fieldOffset,
                            isStatic: isStatic,
                        });
                    }
                } catch(e) {
                    classInfo.fields.push({ error: String(e) });
                }
            }

            // Methods
            if (fn.class_get_methods && fn.method_get_name) {
                try {
                    const iterBuf = Memory.alloc(Process.pointerSize);
                    iterBuf.writePointer(ptr(0));
                    let methodCount = 0;
                    while (methodCount < 500) {
                        const method = fn.class_get_methods(classPtr, iterBuf);
                        if (method.isNull()) break;
                        methodCount++;

                        const methodName = readCStr(fn.method_get_name(method));
                        let returnType = "?";
                        let paramCount = 0;

                        if (fn.method_get_return_type) {
                            const rt = fn.method_get_return_type(method);
                            returnType = getTypeName(rt);
                        }
                        if (fn.method_get_param_count) {
                            paramCount = fn.method_get_param_count(method);
                        }

                        classInfo.methods.push({
                            name: methodName,
                            returnType: returnType,
                            paramCount: paramCount,
                            address: method.toString(),
                        });
                    }
                } catch(e) {
                    classInfo.methods.push({ error: String(e) });
                }
            }

            matchedClasses.push(classInfo);
        }
    }

    console.log(`\nScanned ${totalClasses} classes across ${totalImages} images`);
    console.log(`Found ${matchedClasses.length} classes matching keywords`);

    // ── Send results ──────────────────────────────────────────────────

    // Sort by relevance (classes with more fields/methods first)
    matchedClasses.sort((a, b) => {
        const aScore = a.fields.length + a.methods.length;
        const bScore = b.fields.length + b.methods.length;
        return bScore - aScore;
    });

    // Log summary
    for (const cls of matchedClasses) {
        console.log(`\n  ${cls.fullName} (${cls.image})`);
        if (cls.parent) console.log(`    extends ${cls.parent}`);
        console.log(`    ${cls.fields.length} fields, ${cls.methods.length} methods`);

        for (const f of cls.fields.slice(0, 10)) {
            if (f.error) continue;
            const staticMark = f.isStatic ? " [static]" : "";
            console.log(`      field: ${f.type} ${f.name} (offset ${f.offset})${staticMark}`);
        }
        if (cls.fields.length > 10)
            console.log(`      ... and ${cls.fields.length - 10} more fields`);

        for (const m of cls.methods.slice(0, 15)) {
            if (m.error) continue;
            console.log(`      method: ${m.returnType} ${m.name}(${m.paramCount} params)`);
        }
        if (cls.methods.length > 15)
            console.log(`      ... and ${cls.methods.length - 15} more methods`);
    }

    send({
        type: "results",
        total_classes_scanned: totalClasses,
        total_images: totalImages,
        matched_class_count: matchedClasses.length,
        classes: matchedClasses,
    });

    console.log("\nDone.");
})();
""".replace("KEYWORDS_PLACEHOLDER", json.dumps(SEARCH_KEYWORDS))


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
    log("  Uma Musume IL2CPP Skill Discovery")
    log("  Searching for skill-related classes via IL2CPP introspection")
    log(f"  Keywords: {SEARCH_KEYWORDS}")
    log("=" * 60)
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

                elif ptype == "api_status":
                    log(f"  IL2CPP API: {payload.get('resolved_count', 0)} resolved")
                    if payload.get("missing"):
                        log(f"  Missing: {payload['missing']}")

                elif ptype == "results":
                    results = payload
                    done = True

                elif ptype == "error":
                    error_info = payload
                    done = True
                    log(f"  [X] {payload.get('message', 'Unknown error')}")
                    if payload.get("all_modules"):
                        log(f"  Modules: {payload['all_modules'][:30]}")

        elif msg_type == "error":
            done = True
            error_info = message
            log(f"  [X] JS Error: {message.get('description', '')}")
            stack = message.get("stack")
            if stack:
                for line in str(stack).splitlines()[:10]:
                    log(f"      {line}")

        elif msg_type == "log":
            log(f"  [JS] {message.get('payload', '')}")

    try:
        script = session.create_script(FRIDA_SCRIPT, runtime="v8")
        script.on("message", on_message)
        log("[*] Scanning IL2CPP classes...")
        print("[*] Running il2cpp_skill_scan... see il2cpp_scan.log for output")
        script.load()
    except Exception as e:
        log(f"[X] Failed: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.exit(1)

    # Wait for completion
    for _ in range(MAX_WAIT_SECONDS):
        time.sleep(0.5)
        if done:
            break

    if error_info:
        log()
        log("[X] Script failed. See log for details.")
        sys.exit(1)

    if not results:
        log("[X] No results received (timeout?).")
        sys.exit(1)

    # ── Output ─────────────────────────────────────────────────────────

    log()
    log("=" * 60)
    log("  RESULTS")
    log("=" * 60)
    log(f"  Total classes scanned:  {results.get('total_classes_scanned', 0)}")
    log(f"  Total images:           {results.get('total_images', 0)}")
    log(f"  Matching classes:       {results.get('matched_class_count', 0)}")
    log()

    classes = results.get("classes", [])
    if not classes:
        log("  No skill-related classes found.")
        log("  This might mean:")
        log("    - The game uses a different naming convention")
        log("    - Classes are obfuscated")
        log("    - The game isn't using IL2CPP")
        sys.exit(1)

    # Group by image/assembly
    by_image = {}
    for cls in classes:
        img = cls.get("image", "?")
        if img not in by_image:
            by_image[img] = []
        by_image[img].append(cls)

    for img, img_classes in sorted(by_image.items()):
        log(f"\n  ── {img} ({len(img_classes)} classes) ──")
        for cls in img_classes:
            parent_str = f" : {cls['parent']}" if cls.get('parent') else ""
            log(f"    {cls['fullName']}{parent_str}")

            # Fields
            for f in cls.get("fields", []):
                if "error" in f:
                    continue
                static = " [static]" if f.get("isStatic") else ""
                log(f"      ├ {f['type']} {f['name']} (off={f['offset']}){static}")

            # Interesting methods (skip generic .ctor, getters, etc)
            methods = cls.get("methods", [])
            interesting = [m for m in methods
                           if "error" not in m
                           and m.get("name") not in (".ctor", ".cctor", "Finalize")]
            for m in interesting[:20]:
                log(f"      ├ {m['returnType']} {m['name']}({m['paramCount']}p)")
            if len(interesting) > 20:
                log(f"      └ ... {len(interesting) - 20} more methods")

    # Save full JSON
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    log(f"\n  Full results: {OUTPUT_FILE}")
    log(f"  Debug log:    {LOG_FILE}")

    # ── Highlight particularly interesting classes ─────────────────────

    log()
    log("=" * 60)
    log("  INTERESTING CLASSES (likely candidates)")
    log("=" * 60)

    for cls in classes:
        fields = [f for f in cls.get("fields", []) if "error" not in f]
        methods = [m for m in cls.get("methods", []) if "error" not in m]
        field_names = {f["name"].lower() for f in fields}
        method_names = {m["name"].lower() for m in methods}

        # Score: how "skill-data-like" is this class?
        score = 0
        reasons = []

        if any("id" in fn for fn in field_names):
            score += 1
            reasons.append("has ID field")
        if any("level" in fn for fn in field_names):
            score += 1
            reasons.append("has level field")
        if any("cost" in fn or "point" in fn for fn in field_names):
            score += 1
            reasons.append("has cost/point field")
        if any("list" in fn or "array" in fn or "collection" in fn
               for fn in field_names):
            score += 1
            reasons.append("has list/array field")
        if any("get" in mn and "skill" in mn for mn in method_names):
            score += 1
            reasons.append("has get*skill* method")
        if any("acquire" in mn or "learn" in mn for mn in method_names):
            score += 2
            reasons.append("has acquire/learn method")
        if len(fields) >= 3:
            score += 1
            reasons.append(f"{len(fields)} fields")

        if score >= 2:
            log(f"\n  ★ {cls['fullName']} (score={score})")
            log(f"    Reasons: {', '.join(reasons)}")
            for f in fields:
                log(f"    field: {f['type']} {f['name']} (off={f['offset']})")
            for m in methods[:15]:
                log(f"    method: {m['returnType']} {m['name']}({m['paramCount']}p) @ {m['address']}")

    log()
    log("=" * 60)


if __name__ == "__main__":
    main()

