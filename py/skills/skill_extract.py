# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
# ]
# ///

import argparse
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

# ── CLI ────────────────────────────────────────────────────────────────────

_parser = argparse.ArgumentParser(description="Umamusume Skill Extractor")
_parser.add_argument("--debug", action="store_true",
                     help="Write a detailed log to skill_extract.log")
_args = _parser.parse_args()
DEBUG = _args.debug

# ── Logging ────────────────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(_SCRIPT_DIR, "skill_extract.log")
OUTPUT_TREE = os.path.join(_SCRIPT_DIR, "skill_tree.json")

logger = logging.getLogger("skillextract")
logger.setLevel(logging.DEBUG)

if DEBUG:
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
# A single injected script that installs BOTH the skill-tree hooks and the
# MasterSkillData.Get name-resolution hook so everything fires in one visit.

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
    const apiNames = [
        "il2cpp_domain_get", "il2cpp_domain_get_assemblies",
        "il2cpp_assembly_get_image", "il2cpp_image_get_class_count",
        "il2cpp_image_get_class", "il2cpp_image_get_name",
        "il2cpp_class_get_name", "il2cpp_class_get_namespace",
        "il2cpp_class_get_methods", "il2cpp_class_get_fields",
        "il2cpp_class_get_nested_types",
        "il2cpp_method_get_name", "il2cpp_method_get_param_count",
        "il2cpp_field_get_name", "il2cpp_field_get_offset",
        "il2cpp_class_from_name",
        "il2cpp_string_chars", "il2cpp_string_length",
        "il2cpp_runtime_invoke",
    ];
    for (const n of apiNames) api[n] = resolve(n);

    const critical = [
        "il2cpp_domain_get", "il2cpp_domain_get_assemblies",
        "il2cpp_assembly_get_image", "il2cpp_image_get_class_count",
        "il2cpp_image_get_class", "il2cpp_class_get_name",
        "il2cpp_class_get_namespace", "il2cpp_class_get_methods",
        "il2cpp_method_get_name",
    ];
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
        image_get_name:        api.il2cpp_image_get_name
            ? new NativeFunction(api.il2cpp_image_get_name, "pointer", ["pointer"]) : null,
        class_get_name:        new NativeFunction(api.il2cpp_class_get_name, "pointer", ["pointer"]),
        class_get_namespace:   new NativeFunction(api.il2cpp_class_get_namespace, "pointer", ["pointer"]),
        class_get_methods:     new NativeFunction(api.il2cpp_class_get_methods, "pointer", ["pointer", "pointer"]),
        method_get_name:       new NativeFunction(api.il2cpp_method_get_name, "pointer", ["pointer"]),
        method_get_param_count: api.il2cpp_method_get_param_count
            ? new NativeFunction(api.il2cpp_method_get_param_count, "uint32", ["pointer"]) : null,
        class_get_fields:      api.il2cpp_class_get_fields
            ? new NativeFunction(api.il2cpp_class_get_fields, "pointer", ["pointer", "pointer"]) : null,
        field_get_name:        api.il2cpp_field_get_name
            ? new NativeFunction(api.il2cpp_field_get_name, "pointer", ["pointer"]) : null,
        field_get_offset:      api.il2cpp_field_get_offset
            ? new NativeFunction(api.il2cpp_field_get_offset, "int32", ["pointer"]) : null,
        class_get_nested_types: api.il2cpp_class_get_nested_types
            ? new NativeFunction(api.il2cpp_class_get_nested_types, "pointer", ["pointer", "pointer"]) : null,
        class_from_name:       api.il2cpp_class_from_name
            ? new NativeFunction(api.il2cpp_class_from_name, "pointer", ["pointer", "pointer", "pointer"]) : null,
        string_chars: api.il2cpp_string_chars
            ? new NativeFunction(api.il2cpp_string_chars, "pointer", ["pointer"]) : null,
        string_length: api.il2cpp_string_length
            ? new NativeFunction(api.il2cpp_string_length, "int32", ["pointer"]) : null,
        runtime_invoke: api.il2cpp_runtime_invoke
            ? new NativeFunction(api.il2cpp_runtime_invoke, "pointer", ["pointer", "pointer", "pointer", "pointer"]) : null,
    };

    function readCStr(p) {
        if (!p || p.isNull()) return "";
        try { return p.readUtf8String(); } catch(e) { return ""; }
    }

    function readIl2CppString(strPtr) {
        if (!strPtr || strPtr.isNull()) return "";
        if (fn.string_chars && fn.string_length) {
            try {
                const len = fn.string_length(strPtr);
                if (len <= 0 || len > 500) return "";
                const chars = fn.string_chars(strPtr);
                return chars.readUtf16String(len);
            } catch(e) { return ""; }
        }
        try {
            const len = strPtr.add(0x10).readS32();
            if (len <= 0 || len > 500) return "";
            return strPtr.add(0x14).readUtf16String(len);
        } catch(e) { return ""; }
    }

    // ── IL2CPP List / Array helpers ───────────────────────────────────

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
        if (!arrPtr || arrPtr.isNull()) return null;
        try { return arrPtr.add(0x20 + index * ptrSize).readPointer(); }
        catch(e) { return null; }
    }

    // ── Scan assemblies ───────────────────────────────────────────────

    const domain = fn.domain_get();
    const countBuf = Memory.alloc(4);
    const assembliesPtr = fn.domain_get_assemblies(domain, countBuf);
    const asmCount = countBuf.readU32();

    // ────────────────────────────────────────────────────────────────────
    // PART A — skill-tree target classes (from skill_hook)
    // ────────────────────────────────────────────────────────────────────

    const targets = {};

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
        { ns: "",       name: "Info" },
    ];

    const targetLookup = {};
    for (const t of TARGET_CLASSES) {
        const key = t.ns ? `${t.ns}.${t.name}` : t.name;
        targetLookup[key] = true;
    }

    // ────────────────────────────────────────────────────────────────────
    // PART B — MasterSkillData (from map_skills)
    // ────────────────────────────────────────────────────────────────────

    let masterSkillDataClass = null;
    let skillDataInnerMethods = {};

    // ── Class scanning (single pass for both parts) ───────────────────

    console.log("Scanning for target classes + MasterSkillData...");

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
        const fullName = parentName
            ? `${parentName}.${name}`
            : (ns ? `${ns}.${name}` : name);

        // ── Part A targets ────────────────────────────────────────────
        let isTarget = targetLookup[fullName];
        if (!isTarget && targetLookup[name]) isTarget = true;

        if (isTarget) {
            console.log(`  Found: ${fullName}`);
            const classInfo = { fullName, methods: {}, fields: {} };

            const iter = Memory.alloc(ptrSize);
            iter.writePointer(ptr(0));
            for (let i = 0; i < 500; i++) {
                const method = fn.class_get_methods(classPtr, iter);
                if (method.isNull()) break;
                const mName = readCStr(fn.method_get_name(method));
                const paramCount = fn.method_get_param_count
                    ? fn.method_get_param_count(method) : -1;
                let methodPtr = ptr(0);
                try { methodPtr = method.readPointer(); } catch(e) {}
                classInfo.methods[mName] = classInfo.methods[mName] || [];
                classInfo.methods[mName].push({
                    paramCount,
                    methodInfoAddr: method.toString(),
                    compiledAddr: methodPtr.toString(),
                });
            }

            if (fn.class_get_fields && fn.field_get_name) {
                const fIter = Memory.alloc(ptrSize);
                fIter.writePointer(ptr(0));
                for (let i = 0; i < 200; i++) {
                    const field = fn.class_get_fields(classPtr, fIter);
                    if (field.isNull()) break;
                    const fName = readCStr(fn.field_get_name(field));
                    const fOffset = fn.field_get_offset
                        ? fn.field_get_offset(field) : -1;
                    classInfo.fields[fName] = { offset: fOffset };
                }
            }

            targets[fullName] = classInfo;
        }

        // ── Part B — MasterSkillData ──────────────────────────────────
        if (ns === "Gallop" && name === "MasterSkillData" && !masterSkillDataClass) {
            masterSkillDataClass = classPtr;
            console.log("  Found: Gallop.MasterSkillData");

            // Locate nested SkillData and its getter methods
            if (fn.class_get_nested_types) {
                const nIter = Memory.alloc(ptrSize);
                nIter.writePointer(ptr(0));
                for (let i = 0; i < 20; i++) {
                    const nt = fn.class_get_nested_types(classPtr, nIter);
                    if (nt.isNull()) break;
                    if (readCStr(fn.class_get_name(nt)) === "SkillData") {
                        console.log("  Found: nested SkillData");
                        const mIter = Memory.alloc(ptrSize);
                        mIter.writePointer(ptr(0));
                        for (let mi = 0; mi < 100; mi++) {
                            const m = fn.class_get_methods(nt, mIter);
                            if (m.isNull()) break;
                            const mName = readCStr(fn.method_get_name(m));
                            let compiled = ptr(0);
                            try { compiled = m.readPointer(); } catch(e) {}
                            skillDataInnerMethods[mName] = { methodInfo: m, compiled };
                        }
                        console.log("  SkillData methods: " +
                            Object.keys(skillDataInnerMethods).join(", "));
                        break;
                    }
                }
            }
        }

        // Recurse nested types
        for (const nt of getNestedTypes(classPtr)) {
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

    console.log(`\nFound ${Object.keys(targets).length} target classes` +
        (masterSkillDataClass ? " + MasterSkillData" : ""));

    for (const [cls, info] of Object.entries(targets)) {
        console.log(`\n  ${cls}:`);
        console.log(`    methods: ${Object.keys(info.methods).join(", ")}`);
        console.log(`    fields: ${JSON.stringify(info.fields)}`);
    }

    // ── Install skill-tree hooks (Part A) ─────────────────────────────

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

    console.log("\nInstalling hooks...");

    // Hook 1: MasterAvailableSkillSet.GetListWithAvailableSkillSetIdOrderByIdAsc
    hookMethod(
        "Gallop.MasterAvailableSkillSet",
        "GetListWithAvailableSkillSetIdOrderByIdAsc", 1,
        {
            onEnter(args) { this.setId = args[1].toInt32(); },
            onLeave(retval) {
                try {
                    const listPtr = retval;
                    const count = readListCount(listPtr);
                    const arr = readListItemsArray(listPtr);
                    const skills = [];
                    for (let i = 0; i < count; i++) {
                        const elem = readArrayElement(arr, i);
                        if (!elem || elem.isNull()) continue;
                        skills.push({
                            id:       elem.add(16).readS32(),
                            setId:    elem.add(20).readS32(),
                            skillId:  elem.add(24).readS32(),
                            needRank: elem.add(28).readS32(),
                        });
                    }
                    console.log(`[HOOK] MasterAvailableSkillSet.GetList(${this.setId}) → ${count}`);
                    send({ type: "available_skill_set",
                           availableSkillSetId: this.setId, count, skills });
                } catch(e) { console.log(`[HOOK] Error: ${e}`); }
            }
        }
    );

    // Hook 2: MasterSkillSet.GetSkillDataList
    hookMethod(
        "Gallop.MasterSkillSet",
        "GetSkillDataList", 1,
        {
            onEnter(args) { this.setId = args[1].toInt32(); },
            onLeave(retval) {
                try {
                    const listPtr = retval;
                    const count = readListCount(listPtr);
                    const arr = readListItemsArray(listPtr);
                    const skills = [];
                    for (let i = 0; i < count; i++) {
                        const elem = readArrayElement(arr, i);
                        if (!elem || elem.isNull()) continue;
                        skills.push({
                            skillId: elem.add(16).readS32(),
                            level:   elem.add(20).readS32(),
                        });
                    }
                    console.log(`[HOOK] MasterSkillSet.GetSkillDataList(${this.setId}) → ${count}`);
                    send({ type: "skill_set_data",
                           skillSetId: this.setId, count, skills });
                } catch(e) { console.log(`[HOOK] Error: ${e}`); }
            }
        }
    );

    // Hook 3: PartsSingleModeSkillLearningListItem.GetSkillId
    hookMethod(
        "Gallop.PartsSingleModeSkillLearningListItem",
        "GetSkillId", 0,
        {
            onLeave(retval) {
                const skillId = retval.toInt32();
                if (skillId > 0) send({ type: "learning_item_skill_id", skillId });
            }
        }
    );

    // Hook 4: PartsSingleModeSkillLearningListItem.UpdateItem (4 params)
    const _learningItemFields = (targets["Gallop.PartsSingleModeSkillLearningListItem"] || {}).fields || {};
    const _infoListOffset = (_learningItemFields["_infoList"] || {}).offset;
    if (_infoListOffset == null) console.log("  [WARN] _infoList offset not found, skipping UpdateItem hook");
    _infoListOffset != null && hookMethod(
        "Gallop.PartsSingleModeSkillLearningListItem",
        "UpdateItem", 4,
        {
            onEnter(args) {
                try {
                    const thisPtr = args[0];
                    const infoList = thisPtr.add(_infoListOffset).readPointer();
                    const count = readListCount(infoList);
                    const arr = readListItemsArray(infoList);
                    if (count > 0) {
                        const infos = [];
                        for (let i = 0; i < count; i++) {
                            const info = readArrayElement(arr, i);
                            if (!info || info.isNull()) continue;
                            const fields = [];
                            for (let off = 16; off < 80; off += 4) {
                                try { fields.push(info.add(off).readS32()); }
                                catch(e) { fields.push(0); }
                            }
                            infos.push({ address: info.toString(), fields });
                        }
                        send({ type: "learning_list_item_update",
                               infoCount: count, infos });
                    }
                } catch(e) {}
            }
        }
    );

    // Hook 5: PartsSingleModeSkillListItem.SetAcquire
    const _skillListItemFields = (targets["Gallop.PartsSingleModeSkillListItem"] || {}).fields || {};
    const _infoFieldOffset = (_skillListItemFields["_info"] || {}).offset;
    if (_infoFieldOffset == null) console.log("  [WARN] _info offset not found, skipping SetAcquire hook");
    _infoFieldOffset != null && hookMethod(
        "Gallop.PartsSingleModeSkillListItem",
        "SetAcquire", 0,
        {
            onEnter(args) {
                try {
                    const thisPtr = args[0];
                    const info = thisPtr.add(_infoFieldOffset).readPointer();
                    if (info && !info.isNull()) {
                        const fields = [];
                        for (let off = 16; off < 80; off += 4) {
                            try { fields.push(info.add(off).readS32()); }
                            catch(e) { fields.push(0); }
                        }
                        send({ type: "skill_list_item_acquire",
                               infoAddr: info.toString(), fields });
                    }
                } catch(e) {}
            }
        }
    );

    // Hook 6: MasterAvailableSkillSet.GetFromTalentLevel
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
                        send({ type: "available_from_talent",
                               arg1: this.arg1, arg2: this.arg2, result: null });
                        return;
                    }
                    send({ type: "available_from_talent",
                           arg1: this.arg1, arg2: this.arg2,
                           result: {
                               id:       retval.add(16).readS32(),
                               setId:    retval.add(20).readS32(),
                               skillId:  retval.add(24).readS32(),
                               needRank: retval.add(28).readS32(),
                           }});
                } catch(e) {}
            }
        }
    );

    // Hook 7: SkillInfo.AddInfo
    const skillInfoClass = targets["SkillInfo"]
        || targets["Gallop.SingleModeSkillLearningViewController.SkillInfo"];
    if (skillInfoClass) {
        const className = targets["SkillInfo"] ? "SkillInfo"
            : "Gallop.SingleModeSkillLearningViewController.SkillInfo";
        hookMethod(className, "AddInfo", 2, {
            onEnter(args) {
                send({ type: "skill_info_add_info",
                       skillId: args[1].toInt32(),
                       variant: args[2] ? args[2].toInt32() : -1 });
            }
        });
    }

    // Hook 8: SingleModeSkillLearningViewController.BeginView
    hookMethod(
        "Gallop.SingleModeSkillLearningViewController",
        "BeginView", -1,
        {
            onEnter(args) {
                const controller = args[0];
                try {
                    const skillInfoList = controller.add(64).readPointer();
                    const infoCount = readListCount(skillInfoList);
                    const infoArr = readListItemsArray(skillInfoList);

                    console.log(`[HOOK] BeginView: ${infoCount} SkillInfo groups`);

                    const groups = [];
                    for (let gi = 0; gi < infoCount; gi++) {
                        const skillInfo = readArrayElement(infoArr, gi);
                        if (!skillInfo || skillInfo.isNull()) continue;
                        const skillList = skillInfo.add(16).readPointer();
                        const skillCount = readListCount(skillList);
                        const skillArr = readListItemsArray(skillList);

                        const skills = [];
                        for (let si = 0; si < skillCount; si++) {
                            const info = readArrayElement(skillArr, si);
                            if (!info || info.isNull()) continue;
                            const rawFields = {};
                            for (let off = 16; off <= 128; off += 4) {
                                try { rawFields["off_" + off] = info.add(off).readS32(); }
                                catch(e) { rawFields["off_" + off] = null; break; }
                            }
                            skills.push(rawFields);
                        }
                        groups.push({ groupIndex: gi, skillCount, skills });
                    }

                    console.log(`[HOOK] BeginView: captured ${groups.length} groups`);
                    send({ type: "skill_tree_full", groupCount: infoCount, groups });
                } catch(e) {
                    console.log(`[HOOK] BeginView error: ${e}`);
                }
            }
        }
    );

    // ── Install name-resolution hook (Part B) ─────────────────────────

    const collectedSkills = {};

    if (masterSkillDataClass) {
        const masterMethods = {};
        const mmIter = Memory.alloc(ptrSize);
        mmIter.writePointer(ptr(0));
        for (let i = 0; i < 50; i++) {
            const m = fn.class_get_methods(masterSkillDataClass, mmIter);
            if (m.isNull()) break;
            const mName = readCStr(fn.method_get_name(m));
            let compiled = ptr(0);
            try { compiled = m.readPointer(); } catch(e) {}
            masterMethods[mName] = { methodInfo: m, compiled };
        }

        const getMethod = masterMethods["Get"];
        const getNameMethod = skillDataInnerMethods["get_Name"];
        const getRemarksMethod = skillDataInnerMethods["get_Remarks"];

        if (getMethod && getMethod.compiled && !getMethod.compiled.isNull()) {
            console.log(`  [HOOK] MasterSkillData.Get @ ${getMethod.compiled}`);
            try {
                Interceptor.attach(getMethod.compiled, {
                    onEnter(args) { this.skillId = args[1].toInt32(); },
                    onLeave(retval) {
                        if (retval.isNull()) return;
                        const sid = this.skillId;
                        if (collectedSkills[sid]) return;

                        try {
                            const id           = retval.add(16).readS32();
                            const rarity       = retval.add(20).readS32();
                            const groupId      = retval.add(24).readS32();
                            const gradeValue   = retval.add(36).readS32();
                            const skillCategory = retval.add(40).readS32();

                            let name = "";
                            if (getNameMethod) {
                                try {
                                    const nfn = new NativeFunction(
                                        getNameMethod.compiled, "pointer", ["pointer"]);
                                    const result = nfn(retval);
                                    if (result && !result.isNull())
                                        name = readIl2CppString(result);
                                } catch(e) {
                                    if (fn.runtime_invoke) {
                                        try {
                                            const exc = Memory.alloc(ptrSize);
                                            exc.writePointer(ptr(0));
                                            const result = fn.runtime_invoke(
                                                getNameMethod.methodInfo, retval, ptr(0), exc);
                                            if (result && !result.isNull())
                                                name = readIl2CppString(result);
                                        } catch(e2) {}
                                    }
                                }
                            }

                            let desc = "";
                            if (getRemarksMethod) {
                                try {
                                    const nfn = new NativeFunction(
                                        getRemarksMethod.compiled, "pointer", ["pointer"]);
                                    const result = nfn(retval);
                                    if (result && !result.isNull())
                                        desc = readIl2CppString(result);
                                } catch(e) {}
                            }

                            collectedSkills[sid] = {
                                skillId: id, name, desc,
                                rarity, groupId, gradeValue, skillCategory,
                            };
                            console.log(`  Skill ${id}: "${name}" (r=${rarity})`);
                        } catch(e) {
                            console.log(`  Error reading skill ${sid}: ${e}`);
                        }
                    }
                });
                hookCount++;
                console.log("  Name-resolution hook installed");
            } catch(e) {
                console.log(`  Name-resolution hook failed: ${e}`);
            }
        } else {
            console.log("  [WARN] MasterSkillData.Get not found or null");
        }
    } else {
        console.log("  [WARN] MasterSkillData class not found");
    }

    // ── Ready ─────────────────────────────────────────────────────────

    console.log(`\n${hookCount} hooks installed.`);
    console.log("Navigate to the skill learning screen now.");

    send({
        type: "ready",
        hookCount: hookCount,
        classesFound: Object.keys(targets),
        hasMasterSkillData: !!masterSkillDataClass,
        classDetails: Object.fromEntries(
            Object.entries(targets).map(([k, v]) => [k, {
                methods: Object.keys(v.methods),
                fields: v.fields,
            }])
        ),
    });

    // Periodically send collected skill names back to Python
    setInterval(() => {
        const count = Object.keys(collectedSkills).length;
        if (count > 0) {
            send({ type: "skills_collected", count, skills: collectedSkills });
        }
        send({ type: "heartbeat", collected: count });
    }, 3000);
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


# ── Decode & merge ─────────────────────────────────────────────────────────

def decode_and_save(all_events: list, skill_map: dict):
    """Merge skill-tree events with name mapping and save decoded output."""

    def lookup(sid):
        return skill_map.get(str(sid), skill_map.get(sid, {}))

    # Extract skill_tree_full groups
    skill_tree_groups = []

    for ev in all_events:
        if ev.get("type") == "skill_tree_full":
            for g in ev.get("groups", []):
                for s in g.get("skills", []):
                    skill_tree_groups.append({
                        "groupIndex": g["groupIndex"],
                        "skillId": s.get("off_16", 0),
                        "currentLevel": s.get("off_20", 0),
                        "maxLevel": s.get("off_28", 0),
                        "isAcquired": s.get("off_32", 0),
                        "discountedCost": s.get("off_48", 0),
                        "baseCost": s.get("off_52", 0),
                        "discountPercent": s.get("off_56", 0),
                        "hintLevel": s.get("off_60", 0),
                    })

    # Dedup
    seen = set()
    skill_tree_groups = [
        s for s in skill_tree_groups
        if s["skillId"] not in seen and not seen.add(s["skillId"])
    ]

    # Attach names
    for s in skill_tree_groups:
        info = lookup(s["skillId"])
        s["name"] = info.get("name", "[not collected]")
        s["rarity"] = info.get("rarity", 0)
        s["desc"] = info.get("desc", "")


    # ── Pretty-print ───────────────────────────────────────────────────

    log()
    log("=" * 60)
    log("  DECODED SKILL TREE")
    log("=" * 60)


    acquired = [s for s in skill_tree_groups if s["isAcquired"]]
    buyable = [s for s in skill_tree_groups if not s["isAcquired"]]

    log(f"\n  ALREADY ACQUIRED: {len(acquired)}")
    for s in sorted(acquired, key=lambda x: x["skillId"]):
        log(f"    {s['skillId']:>8}  lvl={s['currentLevel']}  {s['name']}")

    log(f"\n  BUYABLE SKILLS: {len(buyable)}")
    log(f"    {'ID':>8}  {'Cost':>5}  {'Base':>5}  {'Hint':>4}  "
        f"{'Disc':>4}  Name")
    log(f"    {'':->8}  {'':->5}  {'':->5}  {'':->4}  {'':->4}  "
        f"{'':->20}")
    for s in sorted(buyable, key=lambda x: x["groupIndex"]):
        log(f"    {s['skillId']:>8}  {s['discountedCost']:>5}  "
            f"{s['baseCost']:>5}  {s['hintLevel']:>4}  "
            f"{s['discountPercent']:>3}%  {s['name']}")

    # ── Save ───────────────────────────────────────────────────────────

    output = {
        "acquired_skills": [
            {"skillId": s["skillId"], "name": s["name"],
             "currentLevel": s["currentLevel"]}
            for s in sorted(acquired, key=lambda x: x["skillId"])
        ],
        "buyable_skills": [
            {"skillId": s["skillId"], "name": s["name"],
             "baseCost": s["baseCost"], "discountedCost": s["discountedCost"],
             "hintLevel": s["hintLevel"], "discountPercent": s["discountPercent"],
             "rarity": s["rarity"]}
            for s in sorted(buyable, key=lambda x: x["groupIndex"])
        ],
    }

    with open(OUTPUT_TREE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log(f"\n  Saved: {OUTPUT_TREE}")


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("  Umamusume Skill Extractor")
    log("  Single-pass skill tree + name extraction")
    log("=" * 60)
    log()
    log("  INSTRUCTIONS:")
    log("  1. Run this script with the game open")
    log("  2. Navigate to the skill learning screen (during training)")
    log("  3. Wait a few seconds for capture")
    log("  4. Ctrl+C to stop and save results")
    log()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    all_events = []
    collected_skills = {}   # id → {name, rarity, …}
    ready = False
    error_info = None
    class_details = {}

    def on_message(message, data):
        nonlocal ready, error_info, class_details, collected_skills

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
                    log(f"  MasterSkillData: "
                        f"{payload.get('hasMasterSkillData', False)}")
                    for cls, detail in class_details.items():
                        log(f"    {cls}:")
                        log(f"      methods: {detail.get('methods', [])}")
                        log(f"      fields: "
                            f"{json.dumps(detail.get('fields', {}))}")

                elif ptype == "error":
                    error_info = payload
                    log(f"  [X] {payload.get('message', '')}")

                elif ptype == "classes_found":
                    log(f"  Found classes: {payload.get('classes', [])}")

                elif ptype == "skills_collected":
                    new_count = 0
                    for sid, info in payload.get("skills", {}).items():
                        if sid not in collected_skills:
                            new_count += 1
                            collected_skills[sid] = info
                    if new_count > 0:
                        log(f"  +{new_count} skill names "
                            f"(total: {len(collected_skills)})")

                elif ptype == "heartbeat":
                    pass

                elif ptype in ("available_skill_set", "skill_set_data",
                               "learning_item_skill_id",
                               "learning_list_item_update",
                               "skill_list_item_acquire",
                               "available_from_talent",
                               "skill_info_add_info",
                               "skill_tree_full"):
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
        log("[*] Loading hooks...")
        print("[*] Running skill_extract — navigate to skill screen in-game.")
        print("    Ctrl+C to stop.")
        if DEBUG:
            print(f"    Debug log: {LOG_FILE}")
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
    log(f"  Skill names collected: {len(collected_skills)}")

    # Group events by type for summary
    by_type: dict[str, list] = {}
    for ev in all_events:
        by_type.setdefault(ev.get("type", "unknown"), []).append(ev)

    for t, events in by_type.items():
        log(f"\n  {t}: {len(events)} events")
        if t == "available_skill_set":
            for ev in events:
                log(f"    SetId={ev.get('availableSkillSetId')}, "
                    f"Count={ev.get('count')}")
                for s in ev.get("skills", []):
                    log(f"      SkillId={s['skillId']}, "
                        f"NeedRank={s['needRank']}")
        elif t == "skill_set_data":
            for ev in events:
                log(f"    SetId={ev.get('skillSetId')}, "
                    f"Count={ev.get('count')}")
        elif t == "learning_item_skill_id":
            ids = sorted(set(ev["skillId"] for ev in events))
            log(f"    Unique IDs ({len(ids)}): {ids}")
        elif t == "skill_tree_full":
            for ev in events:
                log(f"    Groups: {ev.get('groupCount', 0)}")
                for g in ev.get("groups", []):
                    log(f"      Group {g['groupIndex']}: "
                        f"{g['skillCount']} skills")

    # All unique skill IDs
    all_skill_ids = set()
    for ev in all_events:
        if "skillId" in ev:
            all_skill_ids.add(ev["skillId"])
        for s in ev.get("skills", []):
            if "skillId" in s:
                all_skill_ids.add(s["skillId"])

    if all_skill_ids:
        log(f"\n  ALL UNIQUE SKILL IDs: {sorted(all_skill_ids)}")
        log(f"  Total: {len(all_skill_ids)}")

    # Save skill name map
    if collected_skills:
        for sid in sorted(collected_skills, key=lambda x: int(x)):
            info = collected_skills[sid]
            log(f"    {info.get('skillId', sid):>8}  r={info.get('rarity', '?')}  "
                f"\"{info.get('name', '???')}\"")

    # Decode skill tree with names
    if all_events and collected_skills:
        decode_and_save(all_events, collected_skills)
    elif all_events:
        log("\n  [!] Skill tree captured but no names collected — "
            "saving raw events only.")
        # Still save the raw tree so it's not lost
        with open(OUTPUT_TREE, "w", encoding="utf-8") as f:
            json.dump({"raw_events": all_events}, f, indent=2,
                      ensure_ascii=False)
        log(f"  Saved: {OUTPUT_TREE}")

    if DEBUG:
        log(f"  Log: {LOG_FILE}")
    log("=" * 60)


if __name__ == "__main__":
    main()

