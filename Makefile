# Uma Musume Extractor — Makefile
# Run from: UmaExtractor/
# Requires: python3, frida (pip install frida)
# Game must be running for all targets.

PYTHON := python
PY_DIR := py

.PHONY: help scan-classes hook-skills map-skills extract full clean

help: ## Show this help
	@echo ""
	@echo "  Uma Musume Extractor"
	@echo "  ===================="
	@echo "  Game must be running for all targets."
	@echo ""
	@echo "  Workflow:"
	@echo "    make full           — run the complete pipeline (scan → hook → map)"
	@echo ""
	@echo "  Individual steps:"
	@echo "    make scan-classes   — discover IL2CPP skill classes"
	@echo "    make hook-skills    — capture skill IDs from skill tree"
	@echo "    make map-skills     — collect skill names from game"
	@echo "    make extract        — extract trained character data"
	@echo ""
	@echo "  Other:"
	@echo "    make clean          — remove generated output files"
	@echo ""

# ── Step 1: Discover IL2CPP skill-related classes ──────────────────────────
# Output: il2cpp_scan.log, il2cpp_skill_classes.json
scan-classes:
	@echo "=== Step 1: IL2CPP class discovery ==="
	@echo "  No in-game navigation needed."
	cd $(PY_DIR) && $(PYTHON) il2cpp_skill_scan.py
	@echo "  Done. See py/il2cpp_scan.log"

# ── Step 2: Hook skill tree to capture skill IDs ──────────────────────────
# Output: skill_hook.log, skill_hook_results.json
# Requires: navigate to skill learning screen in-game, then Ctrl+C
hook-skills:
	@echo "=== Step 2: Skill tree hook ==="
	@echo "  >>> Open the skill learning screen in-game <<<"
	@echo "  >>> Then press Ctrl+C after a few seconds   <<<"
	cd $(PY_DIR) && $(PYTHON) skill_hook.py
	@echo "  Done. See py/skill_hook.log"

# ── Step 3: Collect skill names from master data ──────────────────────────
# Output: map_skills.log, skill_id_map.json, decoded_skills.json
# Requires: navigate to skill screen in-game, then Ctrl+C
map-skills:
	@echo "=== Step 3: Skill name collection ==="
	@echo "  >>> Open the skill learning screen in-game <<<"
	@echo "  >>> Then press Ctrl+C after a few seconds   <<<"
	cd $(PY_DIR) && $(PYTHON) map_skills.py
	@echo "  Done. See py/map_skills.log, py/decoded_skills.json"

# ── Extract trained character data (standalone) ───────────────────────────
# Output: explore_results.json
extract:
	@echo "=== Extract trained character data ==="
	cd $(PY_DIR) && $(PYTHON) extract_umas.py
	@echo "  Done."

# ── Full pipeline ─────────────────────────────────────────────────────────
# Runs steps 2 + 3 (skip step 1 since class layout is already known)
full: hook-skills map-skills
	@echo ""
	@echo "=== Pipeline complete ==="
	@echo "  skill_hook_results.json — captured skill IDs"
	@echo "  skill_id_map.json       — skill ID → name mapping"
	@echo "  decoded_skills.json     — final decoded output"
	@echo ""

# ── Clean generated files ─────────────────────────────────────────────────
clean:
	rm -f $(PY_DIR)/il2cpp_scan.log
	rm -f $(PY_DIR)/il2cpp_skill_classes.json
	rm -f $(PY_DIR)/skill_hook.log
	rm -f $(PY_DIR)/skill_hook_results.json
	rm -f $(PY_DIR)/map_skills.log
	rm -f $(PY_DIR)/skill_id_map.json
	rm -f $(PY_DIR)/decoded_skills.json
	rm -f $(PY_DIR)/list_scan.log
	rm -f $(PY_DIR)/il2cpp_lists.json
	@echo "  Cleaned."

