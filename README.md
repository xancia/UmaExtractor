# UmaExtractor (Updated Umadump Fork)

> **Note:** This is an updated fork of the original umadump project. The original version stopped working due to game updates. This version has been rewritten with a more resilient memory scanning approach.

Dump your veteran Uma Musume character list into a JSON file for easy filtering and analysis.

Extract all your trained characters with their stats, skills, and **inheritance factors** (sparks) to find the perfect parents for breeding.

## Features

- Extracts all veteran character data (stats, skills, factors)
- No installation required (standalone executable)
- Works with current game version (as of Jan 2026)
- Outputs clean JSON format for web tools

## Usage

1. **Open Umamusume Pretty Derby** and navigate to the **Veteran List** page (Enhance → List)
2. **Run `umaextractor.exe`** (double-click or run from command line)
3. Wait 10-20 seconds for the scan to complete
4. **`data.json`** will be created in the same folder with all your character data

### Alternative: Python Script

If you have Python 3.10+ with `frida` and `msgpack` installed:
```bash
python py/extract_umas.py
```

### Linux (Steam/Proton)

For Linux users running the game via Steam/Proton:

**Requirements:**
- Python 3.10 or higher
- `msgpack` package: `pip install msgpack`
- Root permissions (required to read process memory)

**Steps:**
1. **Launch Uma Musume Pretty Derby** via Steam and navigate to the **Veteran List** page (Enhance → List)
2. Wait for the page to fully load
3. **Run the Linux extraction script with sudo:**
   ```bash
   sudo python3 py/linux_extract.py
   ```
4. Wait 30-60 seconds for the memory scan to complete
5. **`data.json`** will be created in the current directory (or home directory if permissions fail)

**Note:** Root access is required because the script needs to read process memory from `/proc/<pid>/mem`. The script automatically detects the game process running under Proton/Wine.

## Output Format

The generated `data.json` contains an array of character objects with fields including:
- `card_id`, `chara_id` - Character identifiers
- `speed`, `stamina`, `power`, `guts`, `wiz` - Stats
- `factor_id_array` - Inheritance factors/sparks
- `skill_array` - Learned skills
- `proper_distance_*`, `proper_ground_*` - Aptitudes
- And many more fields for detailed analysis

A sample `data.json` is included in the project root.

## Is This Bannable?

The program only reads game memory - it doesn't modify anything. The game currently has no anti-cheat that detects memory reading. Use at your own discretion.

## Technical Details

This updated version uses improved memory pattern matching that:
- Only searches for the character array marker
- Doesn't rely on adjacent memory structures
- Auto-detects data boundaries using msgpack parsing
- More resilient to game updates

## Credits

- Original umadump concept and implementation
- Updated by community members to work with current game version (2026)
