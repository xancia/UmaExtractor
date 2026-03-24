# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "frida",
#     "msgpack",
# ]
# ///
import frida
import msgpack
import json
import sys
import os
import platform
import time
import traceback

print("=== Uma Musume Veteran Data Extractor ===\n")
print("Attaching to game process...")

TARGET_PROCESS_NAMES = [
    "UmamusumePrettyDerby.exe",
    "UmamusumePrettyDerby",
]
PROCESS_KEYWORDS = ["uma", "musume", "derby", "cygames"]


def safe_pause(prompt="\nPress Enter to exit..."):
    try:
        input(prompt)
    except EOFError:
        # Non-interactive terminal (for example CI or piped execution).
        pass


def print_runtime_diagnostics():
    print("\nEnvironment:")
    print(f"  - OS: {platform.platform()}")
    print(f"  - Python: {sys.version.split()[0]}")
    print(f"  - Frida: {getattr(frida, '__version__', 'unknown')}")


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


def find_candidate_processes():
    try:
        device = frida.get_local_device()
        processes = device.enumerate_processes()
    except Exception as e:
        print(f"[!] Could not enumerate processes for diagnostics: {type(e).__name__}: {e}")
        return []

    candidates = []
    for proc in processes:
        name = (proc.name or "").lower()
        if any(keyword in name for keyword in PROCESS_KEYWORDS):
            candidates.append(proc)

    candidates.sort(key=lambda p: (p.name or "").lower())
    return candidates


def attach_to_game():
    attach_errors = []

    for process_name in TARGET_PROCESS_NAMES:
        try:
            session_obj = frida.attach(process_name)
            print(f"[OK] Attached using process name: {process_name}")
            return session_obj, attach_errors, []
        except Exception as e:
            attach_errors.append((process_name, e))

    candidates = find_candidate_processes()
    if candidates:
        print("[!] Could not attach with default process name.")
        print("    Found similar running processes:")
        for proc in candidates[:10]:
            print(f"  - {proc.name} (pid {proc.pid})")
        for proc in candidates:
            try:
                session_obj = frida.attach(proc.pid)
                print(f"[OK] Attached using detected process: {proc.name} (pid {proc.pid})")
                return session_obj, attach_errors, candidates
            except Exception as e:
                attach_errors.append((f"{proc.name} (pid {proc.pid})", e))

    return None, attach_errors, candidates


session, attach_errors, candidate_processes = attach_to_game()
if session is None:
    print("[X] Error: Could not attach to game process")
    for target, err in attach_errors:
        err_name, err_text, hints = summarize_attach_error(err)
        print(f"  - Attempted {target}: {err_name}: {err_text}")
        for hint in hints:
            print(f"    > {hint}")

    if not candidate_processes:
        print("  - No similar process names were found.")

    print_runtime_diagnostics()
    print("\nQuick checks:")
    print("  1. Open Uma Musume and wait on Enhance -> List (Veteran List)")
    print("  2. Ensure the game is not running as admin unless extractor is also admin")
    print("  3. Temporarily allow the extractor in antivirus / Windows Security")
    safe_pause()
    sys.exit(1)

print("[OK] Connected to game\n")

found_data = None
found_meta = None
scan_completed = False
script_error = None

def on_message(message, data):
    global found_data, found_meta, scan_completed, script_error

    message_type = message.get("type")
    if message_type == "send":
        payload = message.get("payload")
        if isinstance(payload, dict):
            payload_type = payload.get("type")
            if payload_type == "found":
                found_meta = payload
                if data and len(data) > 0:
                    found_data = data
                    print(f"[OK] Received data chunk: {len(data)} bytes")
                    array_len = payload.get("array_len", "unknown")
                    card_count = payload.get("card_count", "unknown")
                    print(f"[OK] Candidate array detected (len={array_len}, card_id matches={card_count})")
            elif payload_type == "scan_complete":
                scan_completed = True
                scanned = payload.get("scanned_regions", "unknown")
                total = payload.get("total_ranges", "unknown")
                print(f"[!] Scan completed with no data hit (scanned {scanned}/{total} filtered regions)")
            else:
                print(f"[JS] {payload}")
        elif isinstance(payload, str):
            print(f"[JS] {payload}")
    elif message_type == "error":
        script_error = message
        print("[X] JavaScript scanner error:")
        print(f"    {message.get('description', 'No description')}")
        stack = message.get("stack")
        if stack:
            print("    Stack:")
            for line in str(stack).splitlines():
                print(f"      {line}")
    elif message_type == "log":
        print(f"[JS] {message.get('payload', '')}")

# Simplified, fast script that just finds and extracts the array
script = session.create_script(r"""
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
                                    scanned_regions: scannedCount
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
""", runtime='v8')

script.on("message", on_message)

try:
    script.load()
except Exception as e:
    # Don't exit on timeout - the script may still be running and find data
    if "timeout" in str(e).lower():
        print(f"[!] Script load timed out, but scan is still running in background...")
        print("    Waiting for results (this may take a minute)...\n")
    else:
        print(f"[X] Error loading script: {type(e).__name__}: {e}")
        print("\nThis may be caused by:")
        print("  - Antivirus blocking the memory scan (try disabling temporarily)")
        print("  - Not running as Administrator (right-click -> Run as admin)")
        print("  - Windows Controlled Folder Access blocking the scan")
        print_runtime_diagnostics()
        safe_pause()
        sys.exit(1)

# Wait for data
MAX_WAIT_SECONDS = 120
print(f"Scanning memory (please wait, this may take up to {MAX_WAIT_SECONDS} seconds)...\n")

# Wait longer and check periodically for data
for i in range(MAX_WAIT_SECONDS):
    time.sleep(1)
    if found_data:
        break
    if scan_completed:
        break
    if (i + 1) % 15 == 0:
        print(f"[...] Still scanning... {i + 1}s elapsed")

# Process the data
if found_data:
    print("Processing data...")
    try:
        # Use Unpacker to handle extra bytes
        unpacker = msgpack.Unpacker(raw=False)
        unpacker.feed(found_data)
        character_array = unpacker.unpack()
        
        if isinstance(character_array, list):
            print(f"[OK] Successfully parsed {len(character_array)} characters")
            
            # Remove personal information
            print("Scrubbing personal information...")
            for char in character_array:
                char.pop('viewer_id', None)
                char.pop('owner_viewer_id', None)
            print("[OK] Removed viewer_id and owner_viewer_id fields")
            
            # Save to JSON - try current directory first, then fallback to Documents
            import os
            output_file = "data.json"
            save_success = False
            
            # Try saving to current directory
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(character_array, f, indent=2, ensure_ascii=False)
                save_success = True
                print(f"[OK] Saved to {os.path.abspath(output_file)}\n")
            except PermissionError:
                # Fallback to user's Documents folder
                docs_folder = os.path.join(os.path.expanduser("~"), "Documents")
                output_file = os.path.join(docs_folder, "data.json")
                try:
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(character_array, f, indent=2, ensure_ascii=False)
                    save_success = True
                    print(f"[OK] Saved to {output_file}\n")
                    print("    (Saved to Documents folder due to permission issue in current directory)")
                except PermissionError:
                    print(f"[X] Error: Permission denied when saving file.")
                    print("    Please make sure data.json is not open in another program,")
                    print("    or try running this program from a different folder.")
                except OSError as e:
                    print(f"[X] Error saving file in Documents folder: {type(e).__name__}: {e}")
            except OSError as e:
                print(f"[X] Error saving file in current directory: {type(e).__name__}: {e}")
            
            if not save_success:
                raise Exception("Could not save data.json in current directory or Documents folder")
            
            # Show summary
            if len(character_array) > 0:
                first_char = character_array[0]
                print("Sample character data:")
                print(f"  - card_id: {first_char.get('card_id', 'N/A')}")
                print(f"  - speed: {first_char.get('speed', 'N/A')}")
                print(f"  - stamina: {first_char.get('stamina', 'N/A')}")
                print(f"  - power: {first_char.get('power', 'N/A')}")
                print(f"  - guts: {first_char.get('guts', 'N/A')}")
                print(f"  - wisdom: {first_char.get('wiz', 'N/A')}")
                
                if 'factor_id_array' in first_char:
                    factors = first_char['factor_id_array']
                    print(f"  - factors: {factors}")
            
            print(f"\n[SUCCESS] Extracted {len(character_array)} veteran umas to data.json")
        else:
            print(f"[X] Error: Expected array but got {type(character_array)}")
    except Exception as e:
        print(f"[X] Error processing data: {e}")
        import traceback
        traceback.print_exc()
else:
    print("[X] No data was extracted")
    if script_error:
        print("  JavaScript scanner reported an internal error. See details above.")
    print("\nTroubleshooting:")
    print("  1. Make sure you're on the Veteran List page (Enhance -> List)")
    print("  2. Wait for the page to fully load")
    print("  3. Try running the script again")
    print("  4. If attach/scanning still fails, run as admin and whitelist in antivirus")

session.detach()
safe_pause()
