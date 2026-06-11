# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "msgpack",
# ]
# ///
import json
import os
import sys

import msgpack

print("=== Uma Musume Veteran Data Extractor (Linux Edition) ===\n")

# Find the game process
print("Searching for game process...")
game_pid = None
game_name = None

# Search for the process
try:
    target = "umamusumeprettyderby.exe"
    candidates = []

    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit():
            continue

        try:
            with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                cmdline_bytes = f.read()
        except (FileNotFoundError, PermissionError):
            continue

        if not cmdline_bytes:
            continue

        argv0 = cmdline_bytes.split(b"\x00", 1)[0].decode("utf-8", "replace")
        if argv0.lower().endswith(target):
            candidates.append((int(pid_dir), argv0))

    if candidates:
        game_pid, game_name = candidates[0]
        if len(candidates) > 1:
            print(f"[!] Multiple game processes found, using PID {game_pid}:")
            for pid, name in candidates:
                print(f"    PID {pid}: {name}")
        print(f"[OK] Found game process: {game_name} (PID: {game_pid})")
    else:
        print("[X] Error: Could not find game process")
        print("  Make sure Uma Musume Pretty Derby is running")
        print("  Looking for: UmamusumePrettyDerby.exe")
        sys.exit(1)

except Exception as e:
    print(f"[X] Error searching for process: {e}")
    sys.exit(1)

# Read memory maps to find readable/writable regions
print("\nReading process memory maps...")
all_regions = []

try:
    with open(f"/proc/{game_pid}/maps", "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue

            # Parse address range
            addr_range = parts[0]
            perms = parts[1]

            # We want read-write regions (rw)
            if "rw" not in perms:
                continue

            # Parse start and end addresses
            start, end = addr_range.split("-")
            start_addr = int(start, 16)
            end_addr = int(end, 16)
            size = end_addr - start_addr

            all_regions.append({"start": start_addr, "end": end_addr, "size": size})

    # Filter and sort ranges: skip tiny (<16KB) and huge (>500MB) ranges
    # Sort by size descending - game data is likely in larger allocations
    memory_regions = [
        r for r in all_regions if r["size"] >= 16 * 1024 and r["size"] <= 500 * 1024 * 1024
    ]
    memory_regions.sort(key=lambda r: r["size"], reverse=True)

    print(
        f"Scanning {len(memory_regions)} memory regions (filtered from {len(all_regions)})..."
    )

except Exception as e:
    print(f"[X] Error reading memory maps: {e}")
    sys.exit(1)

# Search for the data pattern in memory
print("\nSearching for veteran character data...")
print("This may take 30-60 seconds, please wait...\n")

# Pattern: "trained_chara_array" in msgpack format
# B3 = fixstr(19), followed by "trained_chara_array"
# The next byte is the array marker: fixarray (0x90-0x9F), array16 (0xDC), or array32 (0xDD)
pattern = b"\xb3trained_chara_array"

found_data = None
found_location = None

try:
    # Open memory file
    with open(f"/proc/{game_pid}/mem", "rb") as mem:
        scanned_count = 0

        for region in memory_regions:
            scanned_count += 1

            # Progress update every 10 ranges
            if scanned_count % 10 == 0:
                print(
                    f"Progress: {scanned_count}/{len(memory_regions)} regions scanned..."
                )

            try:
                # Seek to region start
                mem.seek(region["start"])

                # Read the entire region
                data = mem.read(region["size"])

                # Search for pattern
                offset = data.find(pattern)

                if offset != -1:
                    print(
                        f"\n[OK] Found pattern at offset {hex(region['start'] + offset)}"
                    )

                    # Array marker starts after: B3(1) + "trained_chara_array"(19) = 20 bytes
                    array_start = offset + 20

                    # Validate msgpack array header (matching Frida logic)
                    if array_start >= len(data):
                        continue
                    first_byte = data[array_start]
                    array_len = -1
                    if 0x90 <= first_byte <= 0x9F:
                        array_len = first_byte - 0x90  # fixarray (0-15 items)
                    elif first_byte == 0xDC and array_start + 2 < len(data):
                        array_len = (data[array_start + 1] << 8) | data[array_start + 2]  # array16
                    elif first_byte == 0xDD and array_start + 4 < len(data):
                        array_len = (
                            (data[array_start + 1] << 24)
                            + (data[array_start + 2] << 16)
                            + (data[array_start + 3] << 8)
                            + data[array_start + 4]
                        )  # array32
                    else:
                        print(f"  Unknown array marker byte: {hex(first_byte)}, skipping")
                        continue

                    print(f"  Array type byte: {hex(first_byte)}, declared length: {array_len}")

                    # Try different sizes (matching Frida script exactly)
                    sizes = [15 * 1024 * 1024, 20 * 1024 * 1024, 25 * 1024 * 1024]

                    for try_size in sizes:
                        try:
                            # Calculate max size we can read from this region
                            max_read_size = min(try_size, region["size"] - array_start)

                            if max_read_size < 1024:
                                continue

                            # Extract the potential array data (include the array marker)
                            potential_data = data[
                                array_start : array_start + max_read_size
                            ]

                            # Quick validation: count occurrences of "card_id"
                            # Check only first 3MB for performance (matching Frida)
                            # Look for: A7 63 61 72 64 5f 69 64 (fixstr(7) + "card_id")
                            card_id_pattern = b"\xa7card_id"
                            check_data = potential_data[:3 * 1024 * 1024]
                            card_count = check_data.count(card_id_pattern)

                            print(
                                f"  Size {try_size // (1024 * 1024)}MB: Found {card_count} card_id entries"
                            )

                            # Accept empty arrays or any array with at least 1 card_id
                            # (matching Frida validation logic)
                            if array_len == 0 or card_count >= 1:
                                print(
                                    f"[OK] Found valid array (len={array_len}) with {card_count} card_id matches!"
                                )
                                found_data = potential_data
                                found_location = hex(region["start"] + array_start)
                                break

                        except Exception as e:
                            continue

                    if found_data:
                        break

            except (OSError, IOError) as e:
                # Some regions may not be readable, skip them
                continue

    if found_data is None:
        print("\n[X] No veteran data found")
        print("\nTroubleshooting:")
        print("  1. Make sure you're on the Veteran List page (Enhance -> Veteran Umamusume -> List)")
        print("  2. Wait for the page to fully load")
        print(
            f"  3. Try running this script as root: sudo python3 {sys.argv[0]}"
        )
        sys.exit(1)

except PermissionError:
    print("\n[X] Permission denied when reading process memory")
    print("  You need to run this script as root:")
    print(f"  sudo python3 {sys.argv[0]}")
    sys.exit(1)
except Exception as e:
    print(f"\n[X] Error reading memory: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)

# Parse the msgpack data
print("\nProcessing data...")
try:
    # Use Unpacker to handle the data
    unpacker = msgpack.Unpacker(raw=False)
    unpacker.feed(found_data)
    character_array = unpacker.unpack()

    if isinstance(character_array, list):
        print(f"[OK] Successfully parsed {len(character_array)} characters")

        # Remove personal information
        print("Scrubbing personal information...")
        for char in character_array:
            char.pop("viewer_id", None)
            char.pop("owner_viewer_id", None)
        print("[OK] Removed viewer_id and owner_viewer_id fields")

        # Save to JSON - try current directory first, then fallback to Documents
        output_file = "data.json"
        save_success = False

        # Try saving to current directory
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(character_array, f, indent=2, ensure_ascii=False)
            save_success = True
            print(f"[OK] Saved to {os.path.abspath(output_file)}\n")
        except PermissionError:
            # Fallback to user's home directory
            home_folder = os.path.expanduser("~")
            output_file = os.path.join(home_folder, "data.json")
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(character_array, f, indent=2, ensure_ascii=False)
                save_success = True
                print(f"[OK] Saved to {output_file}\n")
                print(
                    "    (Saved to home directory due to permission issue in current directory)"
                )
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

            if "factor_id_array" in first_char:
                factors = first_char["factor_id_array"]
                print(f"  - factors: {factors}")

        print(
            f"\n[SUCCESS] Extracted {len(character_array)} veteran umas to {output_file}"
        )
    else:
        print(f"[X] Error: Expected array but got {type(character_array)}")

except Exception as e:
    print(f"[X] Error processing data: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)
