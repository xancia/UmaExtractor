# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
# ]
# ///
"""
Uma Musume Skill Hook
========================
Hooks IL2CPP methods on the skill learning screen to capture
the actual skill IDs displayed to the player.

Targets:
  - MasterAvailableSkillSet.GetListWithAvailableSkillSetIdOrderByIdAsc
  - PartsSingleModeSkillLearningListItem.GetSkillId / UpdateItem
  - MasterSkillSet.GetSkillDataList

Usage:
  1. Start this script with the game running
  2. Open the skill learning screen in-game (during training)
  3. Wait a few seconds
  4. Ctrl+C to stop — results in skill_hook_results.json

Outputs:
  skill_hook.log          — full log
  skill_hook_results.json — captured skill data
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
LOG_FILE = os.path.join(_SCRIPT_DIR, "skill_hook.log")
OUTPUT_FILE = os.path.join(_SCRIPT_DIR, "skill_hook_results.json")

logger = logging.getLogger("skillhook")
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

FRIDA_SCRIPT = r"""
(function() {
    "use strict";

    const ptrSize = Process.pointerSize;

    // ── Find GameAssembly ─────────────────────────────────────────────

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
        send({ type: "error", message: "GameAssembly not found" });
        return;
    }

    // ── Resolve IL2CPP API ────────────────────────────────────────────

    function resolve(name) {
        try {
            if (typeof gaMod.findExportByName === 'function')
                return gaMod.findExportByName(name) || null;
        } catch(e) {}
        try { return Module.findExportByName(gaMod.name, name) || null; }
        catch(e) {}
        return null;
    }

    const api = {};
    const names = [
        "il2cpp_domain_get", "il2cpp_domain_get_assemblies",
        "il2cpp_assembly_get_image", "il2cpp_image_get_class_count",
        "il2cpp_image_get_class", "il2cpp_image_get_name",
        "il2cpp_class_get_name", "il2cpp_class_get_namespace",
        "il2cpp_class_get_methods", "il2cpp_class_get_fields",
        "il2cpp_class_get_nested_types",
        "il2cpp_method_get_name", "il2cpp_method_get_param_count",
        "il2cpp_field_get_name", "il2cpp_field_get_offset",
        "il2cpp_class_from_name",
    ];
    for (const n of names) api[n] = resolve(n);

    // Check critical APIs
    const critical = ["il2cpp_domain_get", "il2cpp_domain_get_assemblies",
                      "il2cpp_assembly_get_image", "il2cpp_image_get_class_count",
                      "il2cpp_image_get_class", "il2cpp_class_get_name",
                      "il2cpp_class_get_namespace", "il2cpp_class_get_methods",
                      "il2cpp_method_get_name"];
    for (const n of critical) {
        if (!api[n]) {
            send({ type: "error", message: `Missing critical API: ${n}` });
            return;
        }
    }

    // ── NativeFunctions ───────────────────────────────────────────────

    const fn = {
        domain_get:            new NativeFunction(api.il2cpp_domain_get, "pointer", []),
        domain_get_assemblies: new NativeFunction(api.il2cpp_domain_get_assemblies, "pointer", ["pointer", "pointer"]),
        assembly_get_image:    new NativeFunction(api.il2cpp_assembly_get_image, "pointer", ["pointer"]),
        image_get_class_count: new NativeFunction(api.il2cpp_image_get_class_count, "uint32", ["pointer"]),
        image_get_class:       new NativeFunction(api.il2cpp_image_get_class, "pointer", ["pointer", "uint32"]),
        image_get_name:        new NativeFunction(api.il2cpp_image_get_name, "pointer", ["pointer"]),
        class_get_name:        new NativeFunction(api.il2cpp_class_get_name, "pointer", ["pointer"]),
        class_get_namespace:   new NativeFunction(api.il2cpp_class_get_namespace, "pointer", ["pointer"]),
        class_get_methods:     new NativeFunction(api.il2cpp_class_get_methods, "pointer", ["pointer", "pointer"]),
        method_get_name:       new NativeFunction(api.il2cpp_method_get_name, "pointer", ["pointer"]),
        method_get_param_count: api.il2cpp_method_get_param_count
            ? new NativeFunction(api.il2cpp_method_get_param_count, "uint32", ["pointer"])
            : null,
        class_get_fields:      api.il2cpp_class_get_fields
            ? new NativeFunction(api.il2cpp_class_get_fields, "pointer", ["pointer", "pointer"])
            : null,
        field_get_name:        api.il2cpp_field_get_name
            ? new NativeFunction(api.il2cpp_field_get_name, "pointer", ["pointer"])
            : null,
        field_get_offset:      api.il2cpp_field_get_offset
            ? new NativeFunction(api.il2cpp_field_get_offset, "int32", ["pointer"])
            : null,
        class_get_nested_types: api.il2cpp_class_get_nested_types
            ? new NativeFunction(api.il2cpp_class_get_nested_types, "pointer", ["pointer", "pointer"])
            : null,
        class_from_name:       api.il2cpp_class_from_name
            ? new NativeFunction(api.il2cpp_class_from_name, "pointer", ["pointer", "pointer", "pointer"])
            : null,
    };

    function readCStr(p) {
        if (!p || p.isNull()) return "";
        try { return p.readUtf8String(); } catch(e) { return ""; }
    }

    // ── Find classes and methods ──────────────────────────────────────

    const domain = fn.domain_get();
    const countBuf = Memory.alloc(4);
    const assembliesPtr = fn.domain_get_assemblies(domain, countBuf);
    const asmCount = countBuf.readU32();

    // Target classes and methods to find
    const targets = {
        // Class full name -> { methods: { methodName: { paramCount, address } } }
    };

    const TARGET_CLASSES = [
        { ns: "Gallop", name: "SingleModeSkillLearningViewController" },
        { ns: "Gallop", name: "SingleModeSkillLearningView" },
        { ns: "Gallop", name: "PartsSingleModeSkillLearningListItem" },
        { ns: "Gallop", name: "PartsSingleModeSkillListItem" },
        { ns: "Gallop", name: "MasterAvailableSkillSet" },
        { ns: "Gallop", name: "MasterSkillSet" },
        { ns: "Gallop", name: "SkillManager" },
        { ns: "",       name: "AvailableSkillSet" },
        { ns: "",       name: "SkillInfo" },
    ];

    const targetLookup = {};
    for (const t of TARGET_CLASSES) {
        const key = t.ns ? `${t.ns}.${t.name}` : t.name;
        targetLookup[key] = true;
    }

    console.log("Scanning for target classes...");

    function getNestedTypes(classPtr) {
        if (!fn.class_get_nested_types) return [];
        const nested = [];
        try {
            const iter = Memory.alloc(ptrSize);
            iter.writePointer(ptr(0));
            for (let i = 0; i < 50; i++) {
                const nt = fn.class_get_nested_types(classPtr, iter);
                if (nt.isNull()) break;
                nested.push(nt);
            }
        } catch(e) {}
        return nested;
    }

    function processClass(classPtr, parentName) {
        const name = readCStr(fn.class_get_name(classPtr));
        const ns = readCStr(fn.class_get_namespace(classPtr));
        const fullName = parentName ? `${parentName}.${name}` : (ns ? `${ns}.${name}` : name);

        // Check if this is a target
        let isTarget = targetLookup[fullName];
        // Also check without namespace for nested types
        if (!isTarget && targetLookup[name]) isTarget = true;

        if (isTarget) {
            console.log(`  Found: ${fullName}`);

            const classInfo = { fullName, methods: {}, fields: {} };

            // Get all methods
            const iter = Memory.alloc(ptrSize);
            iter.writePointer(ptr(0));
            for (let i = 0; i < 500; i++) {
                const method = fn.class_get_methods(classPtr, iter);
                if (method.isNull()) break;

                const mName = readCStr(fn.method_get_name(method));
                const paramCount = fn.method_get_param_count ? fn.method_get_param_count(method) : -1;

                // Store the MethodInfo pointer — we need it to get the actual
                // compiled method address. In IL2CPP, MethodInfo->methodPointer
                // is at offset 0.
                let methodPtr = ptr(0);
                try {
                    methodPtr = method.readPointer();
                } catch(e) {}

                classInfo.methods[mName] = classInfo.methods[mName] || [];
                classInfo.methods[mName].push({
                    paramCount,
                    methodInfoAddr: method.toString(),
                    compiledAddr: methodPtr.toString(),
                });
            }

            // Get fields
            if (fn.class_get_fields && fn.field_get_name) {
                const fIter = Memory.alloc(ptrSize);
                fIter.writePointer(ptr(0));
                for (let i = 0; i < 200; i++) {
                    const field = fn.class_get_fields(classPtr, fIter);
                    if (field.isNull()) break;
                    const fName = readCStr(fn.field_get_name(field));
                    const fOffset = fn.field_get_offset ? fn.field_get_offset(field) : -1;
                    classInfo.fields[fName] = { offset: fOffset };
                }
            }

            targets[fullName] = classInfo;
        }

        // Check nested types
        const nested = getNestedTypes(classPtr);
        for (const nt of nested) {
            processClass(nt, fullName);
        }
    }

    for (let ai = 0; ai < asmCount; ai++) {
        const asmPtr = assembliesPtr.add(ai * ptrSize).readPointer();
        if (asmPtr.isNull()) continue;
        const image = fn.assembly_get_image(asmPtr);
        if (image.isNull()) continue;
        const classCount = fn.image_get_class_count(image);
        for (let ci = 0; ci < classCount; ci++) {
            let classPtr;
            try { classPtr = fn.image_get_class(image, ci); }
            catch(e) { continue; }
            if (!classPtr || classPtr.isNull()) continue;
            processClass(classPtr, null);
        }
    }

    console.log(`\nFound ${Object.keys(targets).length} target classes`);
    send({ type: "classes_found", classes: Object.keys(targets) });

    // ── Report what we found ──────────────────────────────────────────

    for (const [cls, info] of Object.entries(targets)) {
        const methodNames = Object.keys(info.methods);
        const fieldNames = Object.keys(info.fields);
        console.log(`\n  ${cls}:`);
        console.log(`    methods: ${methodNames.join(", ")}`);
        console.log(`    fields: ${JSON.stringify(info.fields)}`);
    }

    // ── Install hooks ─────────────────────────────────────────────────

    const capturedSkills = {};  // method -> [skill data]
    let hookCount = 0;

    function hookMethod(className, methodName, paramCount, callback) {
        const classInfo = targets[className];
        if (!classInfo) {
            console.log(`  [SKIP] Class not found: ${className}`);
            return false;
        }
        const overloads = classInfo.methods[methodName];
        if (!overloads) {
            console.log(`  [SKIP] Method not found: ${className}.${methodName}`);
            return false;
        }
        // Find matching overload
        let match = overloads[0];
        if (paramCount >= 0) {
            const exact = overloads.find(o => o.paramCount === paramCount);
            if (exact) match = exact;
        }

        const addr = ptr(match.compiledAddr);
        if (addr.isNull()) {
            console.log(`  [SKIP] Null address: ${className}.${methodName}`);
            return false;
        }

        try {
            Interceptor.attach(addr, callback);
            hookCount++;
            console.log(`  [HOOK] ${className}.${methodName} @ ${addr}`);
            return true;
        } catch(e) {
            console.log(`  [FAIL] ${className}.${methodName}: ${e}`);
            return false;
        }
    }

    // Helper: read IL2CPP List<T> items
    // List<T> layout (64-bit):
    //   +0x00: klass ptr
    //   +0x08: monitor
    //   +0x10: T[] _items (pointer to backing array)
    //   +0x18: int _size
    // Array layout (64-bit):
    //   +0x00: klass ptr
    //   +0x08: monitor
    //   +0x10: bounds ptr
    //   +0x18: max_length (uint)
    //   +0x20: elements start
    function readListCount(listPtr) {
        if (!listPtr || listPtr.isNull()) return 0;
        try { return listPtr.add(0x18).readS32(); } catch(e) { return 0; }
    }
    function readListItemsArray(listPtr) {
        if (!listPtr || listPtr.isNull()) return null;
        try { return listPtr.add(0x10).readPointer(); } catch(e) { return null; }
    }
    function readArrayLength(arrPtr) {
        if (!arrPtr || arrPtr.isNull()) return 0;
        try { return arrPtr.add(0x18).readU32(); } catch(e) { return 0; }
    }
    function readArrayElement(arrPtr, index) {
        // For reference type arrays, elements are pointers starting at +0x20
        if (!arrPtr || arrPtr.isNull()) return null;
        try { return arrPtr.add(0x20 + index * ptrSize).readPointer(); }
        catch(e) { return null; }
    }
    function readArrayElementInt(arrPtr, index) {
        if (!arrPtr || arrPtr.isNull()) return 0;
        try { return arrPtr.add(0x20 + index * 4).readS32(); }
        catch(e) { return 0; }
    }

    console.log("\nInstalling hooks...");

    // ── Hook 1: MasterAvailableSkillSet.GetListWithAvailableSkillSetIdOrderByIdAsc ──
    // Returns List<AvailableSkillSet>
    // AvailableSkillSet fields: Id(+16), AvailableSkillSetId(+20), SkillId(+24), NeedRank(+28)
    hookMethod(
        "Gallop.MasterAvailableSkillSet",
        "GetListWithAvailableSkillSetIdOrderByIdAsc", 1,
        {
            onEnter(args) {
                this.setId = args[1].toInt32();
            },
            onLeave(retval) {
                try {
                    const listPtr = retval;
                    const count = readListCount(listPtr);
                    const arr = readListItemsArray(listPtr);
                    const skills = [];

                    for (let i = 0; i < count; i++) {
                        const elem = readArrayElement(arr, i);
                        if (!elem || elem.isNull()) continue;
                        const id = elem.add(16).readS32();
                        const setId = elem.add(20).readS32();
                        const skillId = elem.add(24).readS32();
                        const needRank = elem.add(28).readS32();
                        skills.push({ id, setId, skillId, needRank });
                    }

                    console.log(`[HOOK] MasterAvailableSkillSet.GetList(${this.setId}) → ${count} skills`);
                    for (const s of skills) {
                        console.log(`  SkillId=${s.skillId}, NeedRank=${s.needRank}`);
                    }

                    send({
                        type: "available_skill_set",
                        availableSkillSetId: this.setId,
                        count: count,
                        skills: skills,
                    });
                } catch(e) {
                    console.log(`[HOOK] Error reading return: ${e}`);
                }
            }
        }
    );

    // ── Hook 2: MasterSkillSet.GetSkillDataList ──
    // Returns List<SkillData> where SkillData has skill_id(+16), level(+20)
    hookMethod(
        "Gallop.MasterSkillSet",
        "GetSkillDataList", 1,
        {
            onEnter(args) {
                this.setId = args[1].toInt32();
            },
            onLeave(retval) {
                try {
                    const listPtr = retval;
                    const count = readListCount(listPtr);
                    const arr = readListItemsArray(listPtr);
                    const skills = [];

                    for (let i = 0; i < count; i++) {
                        const elem = readArrayElement(arr, i);
                        if (!elem || elem.isNull()) continue;
                        const skillId = elem.add(16).readS32();
                        const level = elem.add(20).readS32();
                        skills.push({ skillId, level });
                    }

                    console.log(`[HOOK] MasterSkillSet.GetSkillDataList(${this.setId}) → ${count} skills`);
                    for (const s of skills) {
                        console.log(`  SkillId=${s.skillId}, Level=${s.level}`);
                    }

                    send({
                        type: "skill_set_data",
                        skillSetId: this.setId,
                        count: count,
                        skills: skills,
                    });
                } catch(e) {
                    console.log(`[HOOK] Error: ${e}`);
                }
            }
        }
    );

    // ── Hook 3: PartsSingleModeSkillLearningListItem.GetSkillId ──
    // Returns int (skill ID)
    hookMethod(
        "Gallop.PartsSingleModeSkillLearningListItem",
        "GetSkillId", 0,
        {
            onLeave(retval) {
                const skillId = retval.toInt32();
                if (skillId > 0) {
                    send({ type: "learning_item_skill_id", skillId });
                }
            }
        }
    );

    // ── Hook 4: PartsSingleModeSkillLearningListItem.UpdateItem (4 params) ──
    // Called when each skill row is populated
    hookMethod(
        "Gallop.PartsSingleModeSkillLearningListItem",
        "UpdateItem", 4,
        {
            onEnter(args) {
                // 'this' (args[0]) is the list item instance
                // _infoList is at offset 200
                try {
                    const thisPtr = args[0];
                    const infoList = thisPtr.add(200).readPointer();
                    const count = readListCount(infoList);
                    const arr = readListItemsArray(infoList);

                    if (count > 0) {
                        const infos = [];
                        for (let i = 0; i < count; i++) {
                            const info = readArrayElement(arr, i);
                            if (!info || info.isNull()) continue;
                            // Try reading skill ID — Info objects may have the skill ID
                            // at various offsets. Read first several int fields.
                            const fields = [];
                            for (let off = 16; off < 80; off += 4) {
                                try { fields.push(info.add(off).readS32()); }
                                catch(e) { fields.push(0); }
                            }
                            infos.push({ address: info.toString(), fields });
                        }
                        send({
                            type: "learning_list_item_update",
                            infoCount: count,
                            infos: infos,
                        });
                    }
                } catch(e) {}
            }
        }
    );

    // ── Hook 5: PartsSingleModeSkillListItem.SetAcquire ──
    // Called when a skill is marked as acquired
    hookMethod(
        "Gallop.PartsSingleModeSkillListItem",
        "SetAcquire", 0,
        {
            onEnter(args) {
                // Read _info at offset 192
                try {
                    const thisPtr = args[0];
                    const info = thisPtr.add(192).readPointer();
                    if (info && !info.isNull()) {
                        const fields = [];
                        for (let off = 16; off < 80; off += 4) {
                            try { fields.push(info.add(off).readS32()); }
                            catch(e) { fields.push(0); }
                        }
                        send({
                            type: "skill_list_item_acquire",
                            infoAddr: info.toString(),
                            fields: fields,
                        });
                    }
                } catch(e) {}
            }
        }
    );

    // ── Hook 6: MasterAvailableSkillSet.GetFromTalentLevel ──
    hookMethod(
        "Gallop.MasterAvailableSkillSet",
        "GetFromTalentLevel", 2,
        {
            onEnter(args) {
                this.arg1 = args[1].toInt32();
                this.arg2 = args[2].toInt32();
            },
            onLeave(retval) {
                try {
                    if (retval.isNull()) {
                        send({ type: "available_from_talent", arg1: this.arg1, arg2: this.arg2, result: null });
                        return;
                    }
                    const id = retval.add(16).readS32();
                    const setId = retval.add(20).readS32();
                    const skillId = retval.add(24).readS32();
                    const needRank = retval.add(28).readS32();
                    send({
                        type: "available_from_talent",
                        arg1: this.arg1,
                        arg2: this.arg2,
                        result: { id, setId, skillId, needRank },
                    });
                } catch(e) {}
            }
        }
    );

    // ── Hook 7: SkillInfo.AddInfo (inner class) ──
    // Called when skills are added to the learning list
    // arg1 = skill ID (int), arg2 = variant flag (0 or 1)
    const skillInfoClass = targets["SkillInfo"]
        || targets["Gallop.SingleModeSkillLearningViewController.SkillInfo"];
    if (skillInfoClass) {
        const className = targets["SkillInfo"] ? "SkillInfo"
            : "Gallop.SingleModeSkillLearningViewController.SkillInfo";
        hookMethod(className, "AddInfo", 2, {
            onEnter(args) {
                const skillId = args[1].toInt32();
                const variant = args[2] ? args[2].toInt32() : -1;
                send({ type: "skill_info_add_info",
                       skillId: skillId,
                       variant: variant });
            }
        });
    }

    console.log(`\n${hookCount} hooks installed.`);
    console.log("Navigate to the skill learning screen now.");
    console.log("Skill data will be captured as methods are called.");

    send({
        type: "ready",
        hookCount: hookCount,
        classesFound: Object.keys(targets),
        classDetails: Object.fromEntries(
            Object.entries(targets).map(([k, v]) => [k, {
                methods: Object.keys(v.methods),
                fields: v.fields,
            }])
        ),
    });

    // Keep alive
    setInterval(() => {
        send({ type: "heartbeat" });
    }, 5000);
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
    log("  Uma Musume Skill Hook")
    log("  Hooks IL2CPP methods to capture skill data")
    log("=" * 60)
    log()
    log("  INSTRUCTIONS:")
    log("  1. Run this script with the game open")
    log("  2. Navigate to the skill learning screen (during training)")
    log("     or open a trained character's detail")
    log("  3. Wait a few seconds for hooks to fire")
    log("  4. Ctrl+C to stop and save results")
    log()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    all_events = []
    ready = False
    error_info = None
    class_details = {}

    def on_message(message, data):
        nonlocal ready, error_info, class_details

        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                ptype = payload.get("type")

                if ptype == "ready":
                    ready = True
                    class_details = payload.get("classDetails", {})
                    log(f"  {payload.get('hookCount', 0)} hooks installed")
                    log(f"  Classes: {payload.get('classesFound', [])}")
                    for cls, detail in class_details.items():
                        log(f"    {cls}:")
                        log(f"      methods: {detail.get('methods', [])}")
                        log(f"      fields: {json.dumps(detail.get('fields', {}))}")

                elif ptype == "error":
                    error_info = payload
                    log(f"  [X] {payload.get('message', '')}")

                elif ptype == "classes_found":
                    log(f"  Found classes: {payload.get('classes', [])}")

                elif ptype == "heartbeat":
                    pass  # silent

                elif ptype in ("available_skill_set", "skill_set_data",
                               "learning_item_skill_id",
                               "learning_list_item_update",
                               "skill_list_item_acquire",
                               "available_from_talent",
                               "skill_info_add_info"):
                    all_events.append(payload)
                    log(f"\n  !! EVENT: {ptype}")
                    log(f"     {json.dumps(payload, indent=2)}")

                else:
                    log(f"  [{ptype}] {json.dumps(payload)}")

        elif msg_type == "error":
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
        log("[*] Loading skill hooks...")
        print("[*] Running skill_hook... navigate to skill screen in-game.")
        print("    See skill_hook.log for live output. Ctrl+C to stop.")
        script.load()
    except Exception as e:
        log(f"[X] Failed: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.exit(1)

    # Wait for ready
    for _ in range(60):
        time.sleep(0.5)
        if ready or error_info:
            break

    if error_info:
        log("\n[X] Script failed.")
        sys.exit(1)

    if not ready:
        log("[*] Hooks may still be loading, continuing...")

    log()
    log("  Hooks active. Navigate to skill screen now.")
    log("  Ctrl+C to stop and save.")

    try:
        for _ in range(MAX_WAIT_SECONDS):
            time.sleep(1)
            if error_info:
                break
    except KeyboardInterrupt:
        log("\n[*] Stopped by user.")

    # ── Save results ───────────────────────────────────────────────────

    log()
    log("=" * 60)
    log("  RESULTS")
    log("=" * 60)
    log(f"  Total events captured: {len(all_events)}")

    # Group by type
    by_type = {}
    for ev in all_events:
        t = ev.get("type", "unknown")
        if t not in by_type:
            by_type[t] = []
        by_type[t].append(ev)

    for t, events in by_type.items():
        log(f"\n  {t}: {len(events)} events")
        if t == "available_skill_set":
            for ev in events:
                log(f"    SetId={ev.get('availableSkillSetId')}, "
                    f"Count={ev.get('count')}")
                for s in ev.get("skills", []):
                    log(f"      SkillId={s['skillId']}, NeedRank={s['needRank']}")
        elif t == "skill_set_data":
            for ev in events:
                log(f"    SetId={ev.get('skillSetId')}, "
                    f"Count={ev.get('count')}")
                for s in ev.get("skills", []):
                    log(f"      SkillId={s['skillId']}, Level={s['level']}")
        elif t == "learning_item_skill_id":
            ids = sorted(set(ev["skillId"] for ev in events))
            log(f"    Unique IDs: {ids}")
            log(f"    Count: {len(ids)}")
        elif t == "skill_info_add_info":
            # Group by variant
            by_variant = {}
            for ev in events:
                v = ev.get("variant", -1)
                if v not in by_variant:
                    by_variant[v] = []
                by_variant[v].append(ev.get("skillId", 0))
            all_add_ids = sorted(set(ev.get("skillId", 0) for ev in events))
            log(f"    All skill IDs added: {all_add_ids}")
            log(f"    Total unique: {len(all_add_ids)}")
            for v, ids in sorted(by_variant.items()):
                log(f"    variant={v}: {sorted(set(ids))} ({len(set(ids))} unique)")

    # Collect all unique skill IDs across all events
    all_skill_ids = set()
    for ev in all_events:
        if "skillId" in ev:
            all_skill_ids.add(ev["skillId"])
        for s in ev.get("skills", []):
            if "skillId" in s:
                all_skill_ids.add(s["skillId"])

    if all_skill_ids:
        log(f"\n  ALL UNIQUE SKILL IDs CAPTURED: {sorted(all_skill_ids)}")
        log(f"  Total: {len(all_skill_ids)}")

    # Save
    output = {
        "total_events": len(all_events),
        "events_by_type": {t: len(evs) for t, evs in by_type.items()},
        "all_unique_skill_ids": sorted(all_skill_ids),
        "unique_skill_id_count": len(all_skill_ids),
        "class_details": class_details,
        "events": all_events,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log(f"\n  Saved: {OUTPUT_FILE}")
    log(f"  Log:   {LOG_FILE}")
    log("=" * 60)


if __name__ == "__main__":
    main()

