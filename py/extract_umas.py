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
    
    const ranges = Process.enumerateRanges({protection: "rw-", coalesce: true});
    let found = false;
    
    for (let i = 0; i < ranges.length && !found; i++) {
        const range = ranges[i];
        
        if (range.size < 100000) continue; // Skip small ranges
        
        try {
            const results = Memory.scanSync(range.base, range.size, pattern);
            
            if (results.length > 0) {
                console.log(`Found ${results.length} potential matches`);
                
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
""")

script.on("message", on_message)

try:
    script.load()
except Exception as e:
    print(f"✗ Error loading script: {e}")
    sys.exit(1)

# Wait for data
import time
print("Scanning memory (please wait 10-20 seconds)...\n")
time.sleep(20)

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
            
            # Save to JSON
            with open("data.json", "w", encoding="utf-8") as f:
                json.dump(character_array, f, indent=2, ensure_ascii=False)
            
            print(f"[OK] Saved to data.json\n")
            
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
