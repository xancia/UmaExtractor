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

print("=== Uma Musume Veteran Data Extractor ===\n")
print("Attaching to game process...")

try:
    session = frida.attach("UmamusumePrettyDerby.exe")
except Exception as e:
    print("[X] Error: Could not attach to game process")
    print("  Make sure UmamusumePrettyDerby.exe is running")
    input("\nPress Enter to exit...")
    sys.exit(1)

print("[OK] Connected to game\n")

found_data = None

def on_message(message, data):
    global found_data
    if data and len(data) > 0:
        found_data = data
        print(f"[OK] Received data chunk: {len(data)} bytes")

# Simplified, fast script that just finds and extracts the array
script = session.create_script(r"""
console.log("Scanning for veteran character data...");

(function() {
    // Look for trained_chara_array key followed by array16 marker
    const pattern = 'B3 74 72 61 69 6E 65 64 5F 63 68 61 72 61 5F 61 72 72 61 79 DC';
    
    const allRanges = Process.enumerateRanges({protection: "rw-", coalesce: true});
    
    // Filter and sort ranges: skip tiny (<100KB) and huge (>500MB) ranges
    // Sort by size descending - game data is likely in larger allocations
    const ranges = allRanges
        .filter(r => r.size >= 100000 && r.size <= 500 * 1024 * 1024)
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
                    // Array starts after: B3(1) + "trained_chara_array"(19) + DC(1) = 21 bytes
                    // But we want to include the DC marker, so skip 20 bytes
                    const arrayStart = result.address.add(20);
                    
                    // Try different sizes
                    const sizes = [15 * 1024 * 1024, 20 * 1024 * 1024, 25 * 1024 * 1024];
                    
                    for (const size of sizes) {
                        try {
                            const maxSize = Math.min(size, range.size - (arrayStart - range.base));
                            const data = arrayStart.readByteArray(maxSize);
                            
                            // Quick check: count occurrences of "card_id"
                            const view = new Uint8Array(data);
                            let cardCount = 0;
                            for (let j = 0; j < Math.min(view.length - 8, 3 * 1024 * 1024); j++) {
                                // Look for fixstr(7) + "card_id" = A7 63 61 72 64 5f 69 64
                                if (view[j] === 0xA7 && view[j+1] === 0x63 && view[j+2] === 0x61 && 
                                    view[j+3] === 0x72 && view[j+4] === 0x64 && view[j+5] === 0x5f && 
                                    view[j+6] === 0x69 && view[j+7] === 0x64) {
                                    cardCount++;
                                    if (cardCount >= 200) break;
                                }
                            }
                            
                            if (cardCount >= 150) {
                                console.log(`Found valid array with ${cardCount}+ characters!`);
                                send('found', data);
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
        print(f"[X] Error loading script: {e}")
        print("\nThis may be caused by:")
        print("  - Antivirus blocking the memory scan (try disabling temporarily)")
        print("  - Not running as Administrator (right-click -> Run as admin)")
        print("  - Windows Controlled Folder Access blocking the scan")
        input("\nPress Enter to exit...")
        sys.exit(1)

# Wait for data
import time
print("Scanning memory (please wait, this may take up to 60 seconds)...\n")

# Wait longer and check periodically for data
for i in range(60):
    time.sleep(1)
    if found_data:
        break

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
            
            if not save_success:
                raise Exception("Could not save data.json - permission denied")
            
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
    print("\nTroubleshooting:")
    print("  1. Make sure you're on the Veteran List page (Enhance -> List)")
    print("  2. Wait for the page to fully load")
    print("  3. Try running the script again")

session.detach()
input("\nPress Enter to exit...")
