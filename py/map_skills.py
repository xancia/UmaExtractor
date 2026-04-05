# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
# ]
# ///
"""
Uma Musume Skill Name Extractor
==================================
Extracts skill ID → name mapping directly from the game's MasterSkillData
via IL2CPP introspection. No external data files needed.

Also decodes skill_hook_results.json if present.

Outputs:
  skill_id_map.json    — full {id: info} mapping from game master data
  decoded_skills.json  — hook results decoded with names
  map_skills.log       — full log

Usage:
  1. Run with game open: python map_skills.py
  2. Navigate to skill learning screen (or any screen showing skills)
  3. Ctrl+C to stop and save
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
LOG_FILE = os.path.join(_SCRIPT_DIR, "map_skills.log")
OUTPUT_MAP = os.path.join(_SCRIPT_DIR, "skill_id_map.json")
OUTPUT_DECODED = os.path.join(_SCRIPT_DIR, "decoded_skills.json")
HOOK_RESULTS = os.path.join(_SCRIPT_DIR, "skill_hook_results.json")

logger = logging.getLogger("mapskills")
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


# ── Frida Script ───────────────────────────────────────────────────────────

FRIDA_SCRIPT = r"""
(function() {
    "use strict";

    const ptrSize = Process.pointerSize;

    const GA_NAMES = ["GameAssembly.dll", "GameAssembly", "libil2cpp.so",
                      "UnityFramework", "GameAssembly.dylib"];
    let gaMod = null;
    for (const name of GA_NAMES) {
        try { gaMod = Process.getModuleByName(name); if (gaMod) break; }
        catch(e) {}
    }
    if (!gaMod) { send({ type: "error", message: "GameAssembly not found" }); return; }

    function resolve(name) {
        try { if (typeof gaMod.findExportByName === 'function') return gaMod.findExportByName(name) || null; } catch(e) {}
        try { return Module.findExportByName(gaMod.name, name) || null; } catch(e) {}
        return null;
    }

    const apiNames = [
        "il2cpp_domain_get", "il2cpp_domain_get_assemblies",
        "il2cpp_assembly_get_image", "il2cpp_image_get_class_count",
        "il2cpp_image_get_class", "il2cpp_class_get_name",
        "il2cpp_class_get_namespace", "il2cpp_class_get_methods",
        "il2cpp_class_get_nested_types",
        "il2cpp_method_get_name", "il2cpp_method_get_param_count",
        "il2cpp_string_chars", "il2cpp_string_length",
        "il2cpp_runtime_invoke",
    ];
    const api = {};
    for (const n of apiNames) api[n] = resolve(n);

    const critical = ["il2cpp_domain_get", "il2cpp_domain_get_assemblies",
                      "il2cpp_assembly_get_image", "il2cpp_image_get_class_count",
                      "il2cpp_image_get_class", "il2cpp_class_get_name",
                      "il2cpp_class_get_namespace", "il2cpp_class_get_methods",
                      "il2cpp_method_get_name"];
    for (const n of critical) {
        if (!api[n]) { send({ type: "error", message: "Missing: " + n }); return; }
    }

    const fn = {};
    fn.domain_get = new NativeFunction(api.il2cpp_domain_get, "pointer", []);
    fn.domain_get_assemblies = new NativeFunction(api.il2cpp_domain_get_assemblies, "pointer", ["pointer", "pointer"]);
    fn.assembly_get_image = new NativeFunction(api.il2cpp_assembly_get_image, "pointer", ["pointer"]);
    fn.image_get_class_count = new NativeFunction(api.il2cpp_image_get_class_count, "uint32", ["pointer"]);
    fn.image_get_class = new NativeFunction(api.il2cpp_image_get_class, "pointer", ["pointer", "uint32"]);
    fn.class_get_name = new NativeFunction(api.il2cpp_class_get_name, "pointer", ["pointer"]);
    fn.class_get_namespace = new NativeFunction(api.il2cpp_class_get_namespace, "pointer", ["pointer"]);
    fn.class_get_methods = new NativeFunction(api.il2cpp_class_get_methods, "pointer", ["pointer", "pointer"]);
    fn.class_get_nested_types = api.il2cpp_class_get_nested_types
        ? new NativeFunction(api.il2cpp_class_get_nested_types, "pointer", ["pointer", "pointer"]) : null;
    fn.method_get_name = new NativeFunction(api.il2cpp_method_get_name, "pointer", ["pointer"]);
    fn.method_get_param_count = api.il2cpp_method_get_param_count
        ? new NativeFunction(api.il2cpp_method_get_param_count, "uint32", ["pointer"]) : null;
    fn.string_chars = api.il2cpp_string_chars
        ? new NativeFunction(api.il2cpp_string_chars, "pointer", ["pointer"]) : null;
    fn.string_length = api.il2cpp_string_length
        ? new NativeFunction(api.il2cpp_string_length, "int32", ["pointer"]) : null;
    fn.runtime_invoke = api.il2cpp_runtime_invoke
        ? new NativeFunction(api.il2cpp_runtime_invoke, "pointer", ["pointer", "pointer", "pointer", "pointer"]) : null;

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
        // Fallback: IL2CPP string layout
        try {
            const len = strPtr.add(0x10).readS32();
            if (len <= 0 || len > 500) return "";
            return strPtr.add(0x14).readUtf16String(len);
        } catch(e) { return ""; }
    }

    // ── Find MasterSkillData class and nested SkillData ───────────────

    const domain = fn.domain_get();
    const countBuf = Memory.alloc(4);
    const assembliesPtr = fn.domain_get_assemblies(domain, countBuf);
    const asmCount = countBuf.readU32();

    let masterSkillDataClass = null;
    let skillDataInnerMethods = {};

    console.log("Scanning for MasterSkillData...");

    for (let ai = 0; ai < asmCount && !masterSkillDataClass; ai++) {
        const asmPtr = assembliesPtr.add(ai * ptrSize).readPointer();
        if (asmPtr.isNull()) continue;
        const image = fn.assembly_get_image(asmPtr);
        if (image.isNull()) continue;
        const cc = fn.image_get_class_count(image);
        for (let ci = 0; ci < cc; ci++) {
            let cls;
            try { cls = fn.image_get_class(image, ci); } catch(e) { continue; }
            if (!cls || cls.isNull()) continue;
            const name = readCStr(fn.class_get_name(cls));
            const ns = readCStr(fn.class_get_namespace(cls));
            if (ns === "Gallop" && name === "MasterSkillData") {
                masterSkillDataClass = cls;
                console.log("  Found Gallop.MasterSkillData");

                // Find nested SkillData
                if (fn.class_get_nested_types) {
                    const iter = Memory.alloc(ptrSize);
                    iter.writePointer(ptr(0));
                    for (let i = 0; i < 20; i++) {
                        const nt = fn.class_get_nested_types(cls, iter);
                        if (nt.isNull()) break;
                        const ntName = readCStr(fn.class_get_name(nt));
                        if (ntName === "SkillData") {
                            console.log("  Found nested SkillData");
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
                            console.log("  SkillData methods: " + Object.keys(skillDataInnerMethods).join(", "));
                            break;
                        }
                    }
                }
                break;
            }
        }
    }

    if (!masterSkillDataClass) {
        send({ type: "error", message: "MasterSkillData not found" });
        return;
    }

    // Get MasterSkillData methods
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

    // ── Hook MasterSkillData.Get(int) to collect skill data + names ───

    const getMethod = masterMethods["Get"];
    const getNameMethod = skillDataInnerMethods["get_Name"];
    const getRemarksMethod = skillDataInnerMethods["get_Remarks"];

    const collectedSkills = {};

    if (getMethod && getMethod.compiled && !getMethod.compiled.isNull()) {
        console.log("Hooking MasterSkillData.Get @ " + getMethod.compiled);
        try {
            Interceptor.attach(getMethod.compiled, {
                onEnter(args) {
                    this.skillId = args[1].toInt32();
                },
                onLeave(retval) {
                    if (retval.isNull()) return;
                    const sid = this.skillId;
                    if (collectedSkills[sid]) return;

                    try {
                        const id = retval.add(16).readS32();
                        const rarity = retval.add(20).readS32();
                        const groupId = retval.add(24).readS32();
                        const gradeValue = retval.add(36).readS32();
                        const skillCategory = retval.add(40).readS32();

                        let name = "";
                        if (getNameMethod) {
                            // Try direct call first (faster)
                            try {
                                const nfn = new NativeFunction(getNameMethod.compiled,
                                    "pointer", ["pointer"]);
                                const result = nfn(retval);
                                if (result && !result.isNull()) name = readIl2CppString(result);
                            } catch(e) {
                                // Fallback: il2cpp_runtime_invoke
                                if (fn.runtime_invoke) {
                                    try {
                                        const exc = Memory.alloc(ptrSize);
                                        exc.writePointer(ptr(0));
                                        const result = fn.runtime_invoke(
                                            getNameMethod.methodInfo, retval, ptr(0), exc);
                                        if (result && !result.isNull()) name = readIl2CppString(result);
                                    } catch(e2) {}
                                }
                            }
                        }

                        let desc = "";
                        if (getRemarksMethod) {
                            try {
                                const nfn = new NativeFunction(getRemarksMethod.compiled,
                                    "pointer", ["pointer"]);
                                const result = nfn(retval);
                                if (result && !result.isNull()) desc = readIl2CppString(result);
                            } catch(e) {}
                        }

                        collectedSkills[sid] = { skillId: id, name, desc, rarity, groupId, gradeValue, skillCategory };
                        console.log("  Skill " + id + ": \"" + name + "\" (r=" + rarity + ")");

                    } catch(e) {
                        console.log("  Error reading skill " + sid + ": " + e);
                    }
                }
            });
            console.log("  Hook installed");
        } catch(e) {
            console.log("  Hook failed: " + e);
        }
    } else {
        console.log("  [WARN] MasterSkillData.Get not found or null address");
    }

    send({ type: "ready",
           hasGetHook: !!(getMethod && getMethod.compiled && !getMethod.compiled.isNull()),
           hasGetName: !!getNameMethod });

    // Send collected skills periodically
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


# ── Decode hook results ───────────────────────────────────────────────────

def decode_hook_results(mapping):
    """Decode skill_hook_results.json using the collected mapping."""
    if not os.path.exists(HOOK_RESULTS):
        log(f"  No hook results at {HOOK_RESULTS}")
        return

    with open(HOOK_RESULTS, "r", encoding="utf-8") as f:
        hook_data = json.load(f)

    events = hook_data.get("events", [])

    all_ids = set()
    for ev in events:
        if "skillId" in ev:
            all_ids.add(ev["skillId"])
        if "arg1_raw" in ev:
            try:
                all_ids.add(int(ev["arg1_raw"], 16))
            except (ValueError, TypeError):
                pass
        for s in ev.get("skills", []):
            if "skillId" in s:
                all_ids.add(s["skillId"])
    for sid in hook_data.get("all_unique_skill_ids", []):
        all_ids.add(sid)

    available_set_skills = []
    add_info_skills = []
    for ev in events:
        if ev.get("type") == "available_skill_set":
            for s in ev.get("skills", []):
                available_set_skills.append(s)
        elif ev.get("type") == "skill_info_add_info":
            sid = ev.get("skillId")
            if sid is None and "arg1_raw" in ev:
                try:
                    sid = int(ev["arg1_raw"], 16)
                except (ValueError, TypeError):
                    continue
            if sid:
                variant = ev.get("variant", ev.get("arg2_raw", "?"))
                if isinstance(variant, str) and variant.startswith("0x"):
                    try:
                        variant = int(variant, 16)
                    except ValueError:
                        pass
                add_info_skills.append({"skillId": sid, "variant": variant})

    def lookup(sid):
        return mapping.get(str(sid), mapping.get(sid, {}))

    log()
    log("=" * 60)
    log("  DECODED SKILL HOOK RESULTS")
    log("=" * 60)

    log(f"\n  CHARACTER-SPECIFIC (MasterAvailableSkillSet):")
    for s in available_set_skills:
        sid = s["skillId"]
        name = lookup(sid).get("name", "[not collected]")
        log(f"    {sid:>8}  NeedRank={s.get('needRank', '?')}  {name}")

    log(f"\n  ALL SKILL TREE ({len(add_info_skills)} entries):")
    variant_1 = [s for s in add_info_skills if s.get("variant") in (1, "0x1")]
    variant_0 = [s for s in add_info_skills if s.get("variant") in (0, "0x0")]

    log(f"\n    variant=1 ({len(variant_1)}):")
    for s in sorted(variant_1, key=lambda x: x["skillId"]):
        name = lookup(s["skillId"]).get("name", "[not collected]")
        log(f"      {s['skillId']:>8}  {name}")

    log(f"\n    variant=0 ({len(variant_0)}):")
    for s in sorted(variant_0, key=lambda x: x["skillId"]):
        name = lookup(s["skillId"]).get("name", "[not collected]")
        log(f"      {s['skillId']:>8}  {name}")

    missing = [sid for sid in sorted(all_ids) if not lookup(sid)]
    if missing:
        log(f"\n  MISSING FROM MAP: {missing}")

    output = {
        "total_unique_skills": len(all_ids),
        "available_skill_set": [
            {**s, "name": lookup(s["skillId"]).get("name", "?")}
            for s in available_set_skills
        ],
        "all_skill_tree_skills": [
            {**s, "name": lookup(s["skillId"]).get("name", "?"),
             "rarity": lookup(s["skillId"]).get("rarity", 0)}
            for s in sorted(add_info_skills, key=lambda x: x["skillId"])
        ],
        "missing_from_map": missing,
    }

    with open(OUTPUT_DECODED, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log(f"\n  Saved: {OUTPUT_DECODED}")


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("  Uma Musume Skill Name Extractor")
    log("  Pulls skill ID → name from in-game MasterSkillData")
    log("=" * 60)
    log()

    session = attach_to_game()
    if session is None:
        sys.exit(1)

    collected_skills = {}
    ready = False
    error_info = None

    def on_message(message, data):
        nonlocal ready, error_info, collected_skills

        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                ptype = payload.get("type")

                if ptype == "ready":
                    ready = True
                    log(f"  Hooks ready. Get={payload.get('hasGetHook')}, "
                        f"Name={payload.get('hasGetName')}")

                elif ptype == "error":
                    error_info = payload
                    log(f"  [X] {payload.get('message', '')}")

                elif ptype == "skills_collected":
                    new_count = 0
                    for sid, info in payload.get("skills", {}).items():
                        if sid not in collected_skills:
                            new_count += 1
                            collected_skills[sid] = info
                    if new_count > 0:
                        log(f"  +{new_count} skills (total: {len(collected_skills)})")

                elif ptype == "heartbeat":
                    pass

        elif msg_type == "error":
            error_info = message
            log(f"  [X] JS Error: {message.get('description', '')}")

        elif msg_type == "log":
            log(f"  [JS] {message.get('payload', '')}")

    try:
        script = session.create_script(FRIDA_SCRIPT, runtime="v8")
        script.on("message", on_message)
        log("[*] Loading skill name hooks...")
        print("[*] Running map_skills — navigate to skill screens in-game.")
        print("    Ctrl+C to stop. See map_skills.log for output.")
        script.load()
    except Exception as e:
        log(f"[X] Failed: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.exit(1)

    for _ in range(30):
        time.sleep(0.5)
        if ready or error_info:
            break

    if error_info:
        log("\n[X] Failed.")
        sys.exit(1)

    log()
    log("  Hooks active. Navigate to skill learning screen or character details.")
    log("  Ctrl+C to stop and save.")

    try:
        for _ in range(MAX_WAIT_SECONDS):
            time.sleep(1)
            if error_info:
                break
    except KeyboardInterrupt:
        log("\n[*] Stopped.")

    # ── Save ───────────────────────────────────────────────────────────

    log()
    log("=" * 60)
    log("  RESULTS")
    log("=" * 60)
    log(f"  Collected {len(collected_skills)} skills")

    for sid in sorted(collected_skills.keys(), key=lambda x: int(x)):
        info = collected_skills[sid]
        log(f"    {info.get('skillId', sid):>8}  r={info.get('rarity', '?')}  "
            f"\"{info.get('name', '???')}\"")

    with open(OUTPUT_MAP, "w", encoding="utf-8") as f:
        json.dump(collected_skills, f, indent=2, ensure_ascii=False)
    log(f"\n  Saved: {OUTPUT_MAP} ({len(collected_skills)} entries)")

    decode_hook_results(collected_skills)

    log(f"  Log: {LOG_FILE}")
    log("=" * 60)


if __name__ == "__main__":
    main()

