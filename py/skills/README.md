# Umamusume Skill Tools

[Frida](https://frida.re)-based scripts that hook into the running game to extract skill data from Umamusume Pretty Derby via IL2CPP introspection.

## Requirements

- Python 3.10+
- `frida` package
- Umamusume Pretty Derby running (Windows, macOS, or Linux)

```bash
pip install frida
```

> If you use [uv](https://docs.astral.sh/uv/) you can run the scripts directly — the inline metadata will handle dependencies automatically:
> ```bash
> uv run skill_extract.py
> ```

## Quick Start — `skill_extract.py`

The combined script captures the **full skill tree** and resolves **skill names** in a single pass. One attach, one visit to the skill screen, done.

**Usage:**

1. **Open the game** and start a training session
2. **Run the script:**
   ```bash
   python skill_extract.py
   ```
3. **Navigate to the skill learning screen** in-game (during training)
4. Wait a few seconds for data capture
5. Press `Ctrl+C` to stop and save results

**Output files:**
| File | Description |
|---|---|
| `skill_extract.log` | Full debug log |
| `skill_id_map.json` | Complete `{id: info}` mapping from game master data |
| `skill_tree.json` | Decoded skill tree — acquired skills, buyable skills (with costs, hint levels, discounts), and character-specific skill set, all with human-readable names |

**Captured data includes:**
- Skill IDs, hint levels, skill point cost (base & discounted)
- Whether a skill is already acquired
- Rare/normal variant pairing
- Skill ID → name mapping, rarity, group ID, grade value, skill category
- Skill descriptions (remarks)
- Character-specific available skill set with rank requirements

---

## Individual Scripts

The standalone scripts are still available if you only need one half of the data.

### `skill_hook.py` — Skill Tree Capture

Hooks the skill learning screen controller to capture the **full skill tree** for the current training session.

**Usage:**

1. **Open the game** and start a training session
2. **Run the script:**
   ```bash
   python skill_hook.py
   ```
3. **Navigate to the skill learning screen** in-game (during training)
4. Wait a few seconds for the `SKILL TREE CAPTURED` message
5. Press `Ctrl+C` to stop and save results

**Output files:**
| File | Description |
|---|---|
| `skill_hook.log` | Full debug log |
| `skill_hook_results.json` | All captured skill data (IDs, costs, hint levels, etc.) |

---

### `map_skills.py` — Skill ID → Name Mapping

Hooks `MasterSkillData.Get()` to build a mapping of skill IDs to their in-game names and metadata. Also decodes `skill_hook_results.json` if present.

**Usage:**

1. **Open the game**
2. **Run the script:**
   ```bash
   python map_skills.py
   ```
3. **Navigate to screens that display skills** — the skill learning screen, character details, etc. Each skill viewed will be recorded.
4. Press `Ctrl+C` to stop and save results

**Output files:**
| File | Description |
|---|---|
| `map_skills.log` | Full debug log |
| `skill_id_map.json` | Complete `{id: info}` mapping from game master data |
| `decoded_skills.json` | Hook results decoded with human-readable names (only generated if `skill_hook_results.json` exists) |

## Troubleshooting

- **"GameAssembly not found"** — The game must be running before you start the script. The scripts auto-detect the process by name or keyword (`uma`, `musume`, `derby`, `cygames`).
- **No events captured** — Make sure you navigate to the correct in-game screen *after* the hooks are installed. The script will print a message when hooks are ready.
- **Permission errors** — On some systems Frida requires elevated privileges to attach to a process. Try running with `sudo` (Linux/macOS) or as Administrator (Windows).
- **Timeout** — The scripts wait up to 10 minutes for data by default. If you need more time, the `MAX_WAIT_SECONDS` constant at the top of each script can be increased.
