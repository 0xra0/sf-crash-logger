# CrashLogger

An [SFSE](https://sfse.silverlock.org/) plugin for Starfield that captures crashes with detailed reports: stack traces, register dumps, RTTI object identification, and minidumps.

## Features

- **Exception handler** installed at preload — catches crashes from all plugins, not just ones that load after us
- **Stack trace** with symbol names and source locations (when PDB is present)
- **Register dump** (RAX–R15, RIP, EFLAGS)
- **RTTI object identification** — reads pointer-sized register values and resolves them to C++ type names via the game's RTTI metadata
- **Minidump** (`.dmp`) compatible with WinDbg / Visual Studio
- **Module list** with base addresses, sizes, and version strings; SFSE plugins flagged separately
- **Startup log** — appends a timestamped line to `CrashLogger.log` every game launch so you can confirm the plugin is active

## Crash log location

```
%USERPROFILE%\Documents\My Games\Starfield\SFSE\Crashlogs\
```

| File | Contents |
|------|----------|
| `CrashLogger.log` | One line per game session — confirms the plugin loaded |
| `crash_<timestamp>.log` | Full crash report (exception, registers, stack, modules) |
| `crash_<timestamp>.dmp` | Minidump for debugger analysis |

## Installation

1. Install [SFSE](https://sfse.silverlock.org/).
2. Download `CrashLogger.dll` from [Releases](../../releases).
3. Place it in `<Starfield>\Data\SFSE\Plugins\`.
4. Launch the game through SFSE.

## Building from source

### Prerequisites

- xmake
- LLVM/Clang with `clang-cl` and `lld-link`
- [xwin](https://github.com/Jake-Shadle/xwin) (for Linux cross-compilation) **or** MSVC on Windows

### Build

```sh
xmake build
```

Output: `build/windows/x64/releasedbg/CrashLogger.dll`

> **Linux cross-compilation**: requires `clang-cl`, `llvm-lib`, `lld-link`, and the xwin Windows SDK at `~/.xwin/`. See the project wiki for the full setup guide.

## License

GPL-3.0 — see [LICENSE](LICENSE).
