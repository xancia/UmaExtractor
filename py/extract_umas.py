# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
import json
import os
import platform
import queue
import sys
import threading
import time
import traceback
import tkinter as tk
from tkinter import scrolledtext, ttk

import frida
import msgpack

TARGET_PROCESS_NAMES = [
    "UmamusumePrettyDerby.exe",
    "UmamusumePrettyDerby",
]
PROCESS_KEYWORDS = ["uma", "musume", "derby", "cygames"]
MAX_WAIT_SECONDS = 120

SCAN_SCRIPT = r"""
console.log("Scanning for veteran character data...");

(function() {
    // Look for the trained_chara_array key. The next byte is the MsgPack array marker:
    // fixarray (0x90-0x9F), array16 (0xDC), or array32 (0xDD).
    const pattern = 'B3 74 72 61 69 6E 65 64 5F 63 68 61 72 61 5F 61 72 72 61 79';
    
    const allRanges = Process.enumerateRanges({protection: "rw-", coalesce: true});
    
    // Filter and sort ranges: skip tiny (<16KB) and huge (>500MB) ranges
    // Sort by size descending - game data is likely in larger allocations
    const ranges = allRanges
        .filter(r => r.size >= 16 * 1024 && r.size <= 500 * 1024 * 1024)
        .sort((a, b) => b.size - a.size);
    
    console.log(`Scanning ${ranges.length} memory regions (filtered from ${allRanges.length})...`);
    
    let found = false;
    let scannedCount = 0;
    
    for (let i = 0; i < ranges.length && !found; i++) {
        const range = ranges[i];
        scannedCount++;

        if (scannedCount === 1 || scannedCount % 5 === 0 || scannedCount === ranges.length) {
            send({
                type: 'scan_progress',
                scanned_regions: scannedCount,
                total_ranges: ranges.length
            });
        }
        
        // Progress update every 10 ranges
        if (scannedCount % 10 === 0) {
            console.log(`Progress: ${scannedCount}/${ranges.length} regions scanned...`);
        }
        
        try {
            const results = Memory.scanSync(range.base, range.size, pattern);
            
            if (results.length > 0) {
                console.log(`Found ${results.length} potential matches in region ${scannedCount}`);
                
                for (const result of results) {
                    // Array starts after: B3(1) + "trained_chara_array"(19) = 20 bytes.
                    // We keep the array marker byte (fixarray/array16/array32) in the payload.
                    const arrayStart = result.address.add(20);
                    
                    // Try different sizes
                    const sizes = [15 * 1024 * 1024, 20 * 1024 * 1024, 25 * 1024 * 1024];
                    
                    for (const size of sizes) {
                        try {
                            const maxSize = Math.min(size, range.size - (arrayStart - range.base));
                            const data = arrayStart.readByteArray(maxSize);
                            
                            const view = new Uint8Array(data);
                            if (view.length < 1) {
                                continue;
                            }

                            // Validate MsgPack array header for small and large player rosters.
                            const first = view[0];
                            let arrayLen = -1;
                            if (first >= 0x90 && first <= 0x9F) {
                                arrayLen = first - 0x90; // fixarray (0-15 items)
                            } else if (first === 0xDC && view.length >= 3) {
                                arrayLen = (view[1] << 8) | view[2]; // array16
                            } else if (first === 0xDD && view.length >= 5) {
                                arrayLen = (((view[1] << 24) >>> 0) + (view[2] << 16) + (view[3] << 8) + view[4]) >>> 0; // array32
                            } else {
                                continue;
                            }

                            // Quick check: count occurrences of "card_id"
                            let cardCount = 0;
                            for (let j = 0; j < Math.min(view.length - 8, 3 * 1024 * 1024); j++) {
                                // Look for fixstr(7) + "card_id" = A7 63 61 72 64 5f 69 64
                                if (view[j] === 0xA7 && view[j+1] === 0x63 && view[j+2] === 0x61 && 
                                    view[j+3] === 0x72 && view[j+4] === 0x64 && view[j+5] === 0x5f && 
                                    view[j+6] === 0x69 && view[j+7] === 0x64) {
                                    cardCount++;
                                }
                            }
                            
                            // Accept tiny/new accounts too. Empty arrays are valid when no veterans exist.
                            if (arrayLen === 0 || cardCount >= 1) {
                                console.log(`Found valid array (len=${arrayLen}) with ${cardCount} card_id matches`);
                                send({
                                    type: 'found',
                                    array_len: arrayLen,
                                    card_count: cardCount,
                                    scanned_regions: scannedCount,
                                    total_ranges: ranges.length
                                }, data);
                                found = true;
                                return;
                            }
                        } catch (e) {
                            continue;
                        }
                    }
                }
            }
        } catch (e) {
            continue;
        }
    }
    
    if (!found) {
        console.log("No data found. Make sure you're on the Veteran List page!");
        send({
            type: 'scan_complete',
            scanned_regions: scannedCount,
            total_ranges: ranges.length
        });
    }
})();
"""


def resource_path(*parts):
    if hasattr(sys, "_MEIPASS"):
        base_dir = getattr(sys, "_MEIPASS")
    else:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(base_dir, *parts)


def runtime_diagnostics_lines():
    return [
        "Environment:",
        f"  - OS: {platform.platform()}",
        f"  - Python: {sys.version.split()[0]}",
        f"  - Frida: {getattr(frida, '__version__', 'unknown')}",
    ]


def summarize_attach_error(err):
    err_name = type(err).__name__
    err_text = str(err)
    lower = f"{err_name} {err_text}".lower()
    hints = []

    if "processnotfound" in lower or "unable to find process" in lower or "not found" in lower:
        hints.append("Game process not found. Launch Uma Musume and stay on the Veteran List screen.")
    if "permission" in lower or "access is denied" in lower or "denied" in lower:
        hints.append("Permission issue. Run game and extractor at the same privilege level (both normal or both admin).")
    if "timed out" in lower or "timeout" in lower:
        hints.append("Attach timed out. Try again after waiting on the Veteran List for 5-10 seconds.")
    if "not supported" in lower or "unsupported" in lower:
        hints.append("This environment may not support this attach method for the running game process.")
    if "frida-server" in lower or "server not running" in lower:
        hints.append("Frida backend is unavailable. Restart the game/PC and run extractor again.")

    return err_name, err_text, hints


def find_candidate_processes(logger):
    try:
        device = frida.get_local_device()
        processes = device.enumerate_processes()
    except Exception as e:
        logger(f"[!] Could not enumerate processes for diagnostics: {type(e).__name__}: {e}")
        return []

    candidates = []
    for proc in processes:
        name = (proc.name or "").lower()
        if any(keyword in name for keyword in PROCESS_KEYWORDS):
            candidates.append(proc)

    candidates.sort(key=lambda p: (p.name or "").lower())
    return candidates


def attach_to_game(logger):
    attach_errors = []

    for process_name in TARGET_PROCESS_NAMES:
        try:
            session_obj = frida.attach(process_name)
            logger(f"[OK] Attached using process name: {process_name}")
            return session_obj, attach_errors, []
        except Exception as e:
            attach_errors.append((process_name, e))

    candidates = find_candidate_processes(logger)
    if candidates:
        logger("[!] Could not attach with default process name.")
        logger("    Found similar running processes:")
        for proc in candidates[:10]:
            logger(f"  - {proc.name} (pid {proc.pid})")
        for proc in candidates:
            try:
                session_obj = frida.attach(proc.pid)
                logger(f"[OK] Attached using detected process: {proc.name} (pid {proc.pid})")
                return session_obj, attach_errors, candidates
            except Exception as e:
                attach_errors.append((f"{proc.name} (pid {proc.pid})", e))

    return None, attach_errors, candidates


def save_output(character_array, logger):
    output_file = os.path.abspath("data.json")
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(character_array, f, indent=2, ensure_ascii=False)
        logger(f"[OK] Saved to {output_file}")
        return output_file
    except PermissionError:
        docs_folder = os.path.join(os.path.expanduser("~"), "Documents")
        output_file = os.path.join(docs_folder, "data.json")
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(character_array, f, indent=2, ensure_ascii=False)
            logger(f"[OK] Saved to {output_file}")
            logger("    (Saved to Documents folder due to permission issue in current directory)")
            return output_file
        except PermissionError as e:
            raise RuntimeError(
                "Permission denied when saving data.json. Close any open data.json file and try again."
            ) from e
        except OSError as e:
            raise RuntimeError(f"Error saving data.json in Documents folder: {type(e).__name__}: {e}") from e
    except OSError as e:
        raise RuntimeError(f"Error saving data.json in current directory: {type(e).__name__}: {e}") from e


def run_extraction(logger, progress=None):
    progress_callback = progress
    if progress_callback is None:
        def noop_progress(_percent, _status=None):
            return
        progress_callback = noop_progress

    def set_progress(percent, status=None):
        try:
            bounded = max(0.0, min(100.0, float(percent)))
        except Exception:
            bounded = 0.0
        progress_callback(bounded, status)

    logger("=== Uma Musume Veteran Data Extractor ===")
    logger("Attaching to game process...")
    set_progress(3, "Attaching to game...")

    session, attach_errors, candidate_processes = attach_to_game(logger)
    if session is None:
        logger("[X] Error: Could not attach to game process")
        for target, err in attach_errors:
            err_name, err_text, hints = summarize_attach_error(err)
            logger(f"  - Attempted {target}: {err_name}: {err_text}")
            for hint in hints:
                logger(f"    > {hint}")
        if not candidate_processes:
            logger("  - No similar process names were found.")
        for line in runtime_diagnostics_lines():
            logger(line)
        logger("Quick checks:")
        logger("  1. Open Uma Musume and wait on Enhance -> List (Veteran List)")
        logger("  2. Ensure the game is not running as admin unless extractor is also admin")
        logger("  3. Temporarily allow the extractor in antivirus / Windows Security")
        set_progress(0, "Attach failed")
        return {"success": False, "error": "attach_failed"}

    logger("[OK] Connected to game")
    set_progress(10, "Attached. Scanning memory...")

    found_data = None
    found_meta = None
    scan_completed = False
    script_error = None

    def on_message(message, data):
        nonlocal found_data, found_meta, scan_completed, script_error

        message_type = message.get("type")
        if message_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                payload_type = payload.get("type")
                if payload_type == "found":
                    found_meta = payload
                    scanned = payload.get("scanned_regions", 0)
                    total = payload.get("total_ranges", 0)
                    if isinstance(scanned, int) and isinstance(total, int) and total > 0:
                        set_progress(10 + (scanned / total) * 75, f"Scanning memory... {scanned}/{total}")
                    if data and len(data) > 0:
                        found_data = data
                        logger(f"[OK] Received data chunk: {len(data)} bytes")
                        array_len = payload.get("array_len", "unknown")
                        card_count = payload.get("card_count", "unknown")
                        logger(f"[OK] Candidate array detected (len={array_len}, card_id matches={card_count})")
                elif payload_type == "scan_complete":
                    scan_completed = True
                    scanned = payload.get("scanned_regions", "unknown")
                    total = payload.get("total_ranges", "unknown")
                    logger(f"[!] Scan completed with no data hit (scanned {scanned}/{total} filtered regions)")
                    set_progress(85, f"Scan complete ({scanned}/{total})")
                elif payload_type == "scan_progress":
                    scanned = payload.get("scanned_regions", 0)
                    total = payload.get("total_ranges", 0)
                    if isinstance(scanned, int) and isinstance(total, int) and total > 0:
                        set_progress(10 + (scanned / total) * 75, f"Scanning memory... {scanned}/{total}")
                else:
                    logger(f"[JS] {payload}")
            elif isinstance(payload, str):
                logger(f"[JS] {payload}")
        elif message_type == "error":
            script_error = message
            logger("[X] JavaScript scanner error:")
            logger(f"    {message.get('description', 'No description')}")
            stack = message.get("stack")
            if stack:
                logger("    Stack:")
                for line in str(stack).splitlines():
                    logger(f"      {line}")
        elif message_type == "log":
            logger(f"[JS] {message.get('payload', '')}")

    script = None
    try:
        script = session.create_script(SCAN_SCRIPT, runtime="v8")
        script.on("message", on_message)
        try:
            script.load()
        except Exception as e:
            if "timeout" in str(e).lower():
                logger("[!] Script load timed out, but scan is still running in background...")
                logger("    Waiting for results (this may take a minute)...")
            else:
                logger(f"[X] Error loading script: {type(e).__name__}: {e}")
                logger("This may be caused by:")
                logger("  - Antivirus blocking the memory scan")
                logger("  - Not running as Administrator")
                logger("  - Windows Controlled Folder Access blocking the scan")
                for line in runtime_diagnostics_lines():
                    logger(line)
                set_progress(0, "Scanner load failed")
                return {"success": False, "error": "script_load_failed"}

        logger(f"Scanning memory (please wait, this may take up to {MAX_WAIT_SECONDS} seconds)...")
        for i in range(MAX_WAIT_SECONDS):
            time.sleep(1)
            if found_data or scan_completed:
                break
            if (i + 1) % 15 == 0:
                logger(f"[...] Still scanning... {i + 1}s elapsed")

        if not found_data:
            logger("[X] No data was extracted")
            if script_error:
                logger("  JavaScript scanner reported an internal error. See details above.")
            logger("Troubleshooting:")
            logger("  1. Make sure you're on the Veteran List page (Enhance -> List)")
            logger("  2. Wait for the page to fully load")
            logger("  3. Try running again")
            logger("  4. If attach/scanning still fails, run as admin and whitelist in antivirus")
            set_progress(0, "No data found")
            return {"success": False, "error": "no_data"}

        logger("Processing data...")
        set_progress(88, "Processing data...")
        unpacker = msgpack.Unpacker(raw=False)
        unpacker.feed(found_data)
        character_array = unpacker.unpack()
        if not isinstance(character_array, list):
            logger(f"[X] Error: Expected array but got {type(character_array)}")
            set_progress(0, "Unexpected data format")
            return {"success": False, "error": "unexpected_payload"}

        logger(f"[OK] Successfully parsed {len(character_array)} characters")
        set_progress(92, "Parsed data. Scrubbing personal fields...")
        logger("Scrubbing personal information...")
        for char in character_array:
            char.pop("viewer_id", None)
            char.pop("owner_viewer_id", None)
        logger("[OK] Removed viewer_id and owner_viewer_id fields")

        set_progress(96, "Saving data.json...")
        output_file = save_output(character_array, logger)
        if len(character_array) > 0:
            first_char = character_array[0]
            logger("Sample character data:")
            logger(f"  - card_id: {first_char.get('card_id', 'N/A')}")
            logger(f"  - speed: {first_char.get('speed', 'N/A')}")
            logger(f"  - stamina: {first_char.get('stamina', 'N/A')}")
            logger(f"  - power: {first_char.get('power', 'N/A')}")
            logger(f"  - guts: {first_char.get('guts', 'N/A')}")
            logger(f"  - wisdom: {first_char.get('wiz', 'N/A')}")
            if "factor_id_array" in first_char:
                logger(f"  - factors: {first_char['factor_id_array']}")

        logger(f"[SUCCESS] Extracted {len(character_array)} veteran umas to data.json")
        set_progress(100, f"Done. Extracted {len(character_array)} veteran umas.")
        return {
            "success": True,
            "count": len(character_array),
            "output_file": output_file,
            "scan_meta": found_meta,
        }
    except Exception as e:
        logger(f"[X] Error processing data: {e}")
        logger(traceback.format_exc())
        set_progress(0, "Extraction failed")
        return {"success": False, "error": "processing_failed", "details": str(e)}
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        try:
            session.detach()
        except Exception:
            pass


class UmaExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("UmaExtractor")
        self._set_window_icon()
        self.root.geometry("920x640")
        self.root.minsize(760, 500)

        self.message_queue = queue.Queue()
        self.is_running = False
        self.last_output_file = None

        self._build_ui()
        self.root.after(100, self._drain_queue)

    def _set_window_icon(self):
        icon_path = resource_path("assets", "umaguide_logo.ico")
        if not os.path.exists(icon_path):
            return
        try:
            self.root.iconbitmap(icon_path)
        except Exception:
            # Keep running even if icon loading fails on a specific platform/environment.
            pass

    def _build_ui(self):
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(container, text="Uma Musume Veteran Data Extractor", font=("Segoe UI", 14, "bold"))
        title.pack(anchor="w")

        help_text = (
            "1) Open Uma Musume and go to Enhance -> List (Veteran List)\n"
            "2) Click Start Extraction\n"
            "3) Wait for completion, then check data.json"
        )
        help_label = ttk.Label(container, text=help_text, justify=tk.LEFT)
        help_label.pack(anchor="w", pady=(6, 10))

        btn_row = ttk.Frame(container)
        btn_row.pack(fill=tk.X, pady=(0, 8))

        self.start_btn = ttk.Button(btn_row, text="Start Extraction", command=self._start_extraction)
        self.start_btn.pack(side=tk.LEFT)

        self.open_btn = ttk.Button(btn_row, text="Open Output Folder", command=self._open_output_folder)
        self.open_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.copy_btn = ttk.Button(btn_row, text="Copy Log", command=self._copy_log)
        self.copy_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(container, textvariable=self.status_var)
        status_label.pack(anchor="w")

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress = ttk.Progressbar(
            container,
            mode="determinate",
            maximum=100,
            variable=self.progress_var,
        )
        self.progress.pack(fill=tk.X, pady=(6, 8))

        self.log_box = scrolledtext.ScrolledText(container, wrap=tk.WORD, height=24, font=("Consolas", 10))
        self.log_box.pack(fill=tk.BOTH, expand=True)
        self.log_box.configure(state=tk.DISABLED)

    def _enqueue_log(self, message):
        self.message_queue.put(("log", message))

    def _enqueue_progress(self, percent, status=None):
        self.message_queue.put(("progress", {"percent": percent, "status": status}))

    def _append_log(self, message):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {message}\n"
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, line)
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    def _set_running(self, running):
        self.is_running = running
        if running:
            self.start_btn.configure(state=tk.DISABLED)
        else:
            self.start_btn.configure(state=tk.NORMAL)

    def _start_extraction(self):
        if self.is_running:
            return
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.delete("1.0", tk.END)
        self.log_box.configure(state=tk.DISABLED)
        self.progress_var.set(0.0)
        self.status_var.set("Running extraction...")
        self._set_running(True)

        worker = threading.Thread(target=self._worker_run_extraction, daemon=True)
        worker.start()

    def _worker_run_extraction(self):
        result = run_extraction(self._enqueue_log, progress=self._enqueue_progress)
        self.message_queue.put(("done", result))

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.message_queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "progress":
                    percent = payload.get("percent")
                    status = payload.get("status")
                    try:
                        self.progress_var.set(max(0.0, min(100.0, float(percent))))
                    except Exception:
                        pass
                    if status:
                        self.status_var.set(status)
                elif kind == "done":
                    self._set_running(False)
                    if payload.get("success"):
                        self.last_output_file = payload.get("output_file")
                        count = payload.get("count", 0)
                        self.progress_var.set(100.0)
                        self.status_var.set(f"Done. Extracted {count} veteran umas.")
                    else:
                        self.status_var.set("Extraction failed. See log for details.")
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _open_output_folder(self):
        target = os.path.dirname(self.last_output_file) if self.last_output_file else os.getcwd()
        if os.path.isdir(target):
            os.startfile(target)

    def _copy_log(self):
        content = self.log_box.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.status_var.set("Log copied to clipboard.")


def safe_pause(prompt="\nPress Enter to exit..."):
    try:
        input(prompt)
    except EOFError:
        pass


def run_cli():
    def logger(msg):
        print(msg)

    result = run_extraction(logger)
    safe_pause()
    return 0 if result.get("success") else 1


def run_gui():
    root = tk.Tk()
    UmaExtractorApp(root)
    root.mainloop()


if __name__ == "__main__":
    if "--cli" in sys.argv:
        sys.exit(run_cli())
    run_gui()
