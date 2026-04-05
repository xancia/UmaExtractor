# Umamusume Skill Tools

[Frida](https://frida.re)-based script that hooks into the running game to extract the full skill tree from Umamusume Pretty Derby via IL2CPP introspection.

## Requirements

- Python 3.10+
- `frida` package
- Umamusume Pretty Derby running (Windows, macOS, or Linux)

```bash
pip install frida
```

> If you use [uv](https://docs.astral.sh/uv/) you can run the script directly — the inline metadata will handle dependencies automatically:
> ```bash
> uv run skill_extract.py
> ```

## Usage — `skill_extract.py`

Captures the **full skill tree** with human-readable names in a single pass. One attach, one visit to the skill screen, done.

1. **Open the game** and start a training session
2. **Run the script:**
   ```bash
   python skill_extract.py
   ```
3. **Navigate to the skill learning screen** in-game (during training)
4. Wait a few seconds for data capture
5. Press `Ctrl+C` to stop and save results

### Output

A single file: **`skill_tree.json`**

Contains two arrays:
- **`acquired_skills`** — skills already learned (ID, name, current level)
- **`buyable_skills`** — skills available for purchase (ID, name, base cost, discounted cost, hint level, discount %, rarity)

### Debug mode

Pass `--debug` to write a detailed log file for troubleshooting:

```bash
python skill_extract.py --debug
```

This produces `skill_extract.log` with full hook output, class/method discovery, and raw event data.

## Compatibility

This script works by hooking internal IL2CPP functions and reading game class layouts (field offsets, method signatures) at runtime. If a game update changes these — e.g. renamed classes/methods, shifted field offsets, or a Unity/IL2CPP version bump — the script will need updating to match.

## Troubleshooting

- **"GameAssembly not found"** — The game must be running before you start the script. The script auto-detects the process by name or keyword (`uma`, `musume`, `derby`, `cygames`).
- **No events captured** — Make sure you navigate to the correct in-game screen *after* the hooks are installed. The script will print a message when hooks are ready.
- **Permission errors** — On some systems Frida requires elevated privileges to attach to a process. Try running with `sudo` (Linux/macOS) or as Administrator (Windows).
- **Timeout** — The script waits up to 10 minutes for data by default. If you need more time, the `MAX_WAIT_SECONDS` constant at the top can be increased.
