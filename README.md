# MCESP - MECCHA CHAMELEON External ESP + Aimbot

A fully external ESP and aimbot for **MECCHA CHAMELEON** (Steam / UE5.6). No DLL injection into the game, no UE4SS dependency - it pattern-scans the running game process and reads (and, for the aimbot, writes a small amount of) memory through `pymem`.

## Features

**ESP**
- Player Marker with 3 styles: **Dot**, **Box Outline**, or **Skeleton** (a real bone-driven skeleton, not an approximation - it's built from the game's actual live bone poses and hierarchy)
- Show/hide local player, names, distance, snap lines, debug counters
- Separate enemy/local marker colors (color pickers)
- Adjustable dot radius, model height, Y offset - all sliders

**Aimbot**
- Adjustable FOV circle and **Strength** (how snappy vs. smooth the aim-assist is)
- Adjustable target offset (aim at center mass by default, raise for head/chest)
- Rebindable aim key, or **keyless mode** - clear the bind and it aims continuously whenever Aimbot Enabled is checked, no key needed
- Hard-capped turn rate - it can't instantly snap your view, even in edge cases

**Quality of life**
- Everything above is a slider/checkbox/dropdown in an in-game menu, no config file editing needed
- **Save Settings** / **Load Settings** buttons - your setup also auto-loads on the next launch
- Rebindable menu-toggle key and aimbot key (click "Record Key", press anything)
- Ctrl+C in the terminal exits cleanly

## Requirements

- Windows 10/11
- Python 3.11+
- Game running in windowed/borderless mode

```bash
pip install pymem PyQt5 pywin32
```

## Usage

1. Launch MECCHA CHAMELEON and get into a match/lobby.
2. Run:
   ```bash
   python esp.py
   ```
3. It'll print `Waiting on game...` if the game isn't open yet, then wait for it. Once found: `Waiting on injection...` then `Injected` - this is just it attaching to read memory, not actually injecting anything into the game.
4. A transparent overlay appears over the game window, plus a settings menu.
5. Configure everything from the menu, then optionally hit **Save Settings** so it's there next time.

## Keybinds (all rebindable in the menu)

| Key | Action |
|---|---|
| `Insert` or `F1` | Show/hide the settings menu |
| `F2` (default) | Toggle ESP on/off |
| `MB5` (default) | Hold to aim (if a key is bound). Clear it in the menu for always-on aimbot |
| `Ctrl+C` (in terminal) | Quit |

To rebind the ESP toggle or aim key: click **Record Key** next to it in the menu, then press any key/mouse button. Click **Clear** next to the aim key to go keyless.

> The ESP reads `GameState -> PlayerArray` for other players - you need to actually be in a match/lobby with someone else for enemy markers to show up. Enable **Show Local Player** in the menu to sanity-check the overlay/projection is working even by yourself.

## Notes / troubleshooting

- Everything except two specific offsets is found dynamically via the engine's own reflection data, so it should keep working across most game patches. The **skeleton marker specifically** relies on two hardcoded offsets (bone pose cache + bone name table) found by manually scanning this exact game build (5.6.1) - if a future update breaks *only* the skeleton view (dot/box still fine), that's why; ping whoever set this up to re-find them.
- The script expects the game window title `Chameleon  `. If that ever changes, `Overlay._find_game_window()` needs updating.
- Settings save to `esp_config.json` next to `esp.py`.

## Disclaimer

This project is provided for **educational and research purposes only**, intended for private, consensual matches with friends. Using cheats or unauthorized third-party tools in online games may violate the game's Terms of Service and can result in account suspension or permanent ban. The authors assume no liability for any damages, bans, or other consequences resulting from the use or misuse of this software. Use at your own risk, and only with people who know it's running.
