# CrashLogger

An [SFSE](https://sfse.silverlock.org/) plugin for Starfield that captures crashes with detailed reports: stack traces, register dumps, RTTI object identification, and minidumps.

## Features

- **Exception handler** installed at preload — catches crashes from all plugins, not just ones that load after us
- **Early-warning breadcrumb trace** — a continuously-appended, crash-durable log (`CrashLogger_trace.log`) of first-chance exceptions and lifecycle markers written *before* the crash. Uses raw `WriteFile` (survives `TerminateProcess`, unlike a buffered stream) and an allocation-free path (works on a corrupted heap), so it leaves evidence even for the crashes that produce **no `.dmp` and no crash log** — stack overflows, fail-fast/heap-corruption trips, and hard kills. The last breadcrumbs are also embedded in each crash report
- **Termination / fail-fast backstop** — IAT hooks on `RaiseFailFastException`, self-`TerminateProcess`, and `std::terminate` capture a stack and emit a full `.log`+`.dmp` for abnormal exits that bypass the normal SEH filter. (A raw compiler `__fastfail`/`int 29h` — a smashed `/GS` cookie or heap-manager corruption trip — still can't be caught in-process; for those the Wine/Proton log via `PROTON_LOG=1` is the source of truth.)
- **Fault analysis** — classifies the access violation and names the faulting module inline: near-null dereference + field offset, `-1`/sentinel pointer, and **debug-allocator poison patterns** (`0xCDCD…` uninitialized, `0xDDDD…`/`0xFEEE…` use-after-free, etc.). It also **ties the fault address back to a register** — `access via RCX+0x38 (field of RCX = 0xCDCD… — uninitialized heap)` — so the base pointer, the field offset, and the bug class are all read straight from the log
- **Fault region** — asks the memory manager what the faulting address actually *is*, separating failure shapes that look identical from the address alone: `MEM_FREE` (never allocated — a wild or stale pointer), reserved-but-never-committed, or committed with its protection decoded. It then says why the access was refused — a write to read-only memory, or an execute of a non-executable page (DEP) — and if the address lies inside the faulting thread's own stack on a page the stack never grew into, it names it: **stack overflow**
- **Culprit summary** — lists every SFSE plugin found anywhere on the stack, so "which mod was running" is answered without a debugger
- **Crashing thread** — names the faulting thread and says whether it is the game's main thread (`Thread: 4812 "TaskThread 3" (not the main thread)`). The same fault on a worker and on the main thread are different bugs. Names are read from `SetThreadDescription` *and* from the legacy `MS_VC_EXCEPTION` handshake — which is not an API but a first-chance exception addressed to a debugger — captured by an observe-only VEH into a fixed, allocation-free table, so it works on a corrupted heap
- **Address Library IDs** — every game-executable address (fault site, stack frames, register targets) is also annotated with its Address Library ID (`ID: 449566+0x2A`), the stable identifier mod authors and other crash logs share, making crashes comparable across game versions and searchable. Reads `versionlib-<ver>.bin` from the plugins folder itself (both the delta-encoded v1/v2 and the direct v5 formats); if no database matching the running game version is present, IDs are simply omitted — nothing else changes
- **Crash signature** — an eight-hex-digit identifier for *this kind of crash* (`Crash signature: E70112EE`), so two users can tell whether they hit the same bug and duplicate reports group without anyone reading two stack traces side by side. It hashes the exception code, the access type, and the **Address Library IDs** of the fault site and its three callers — deliberately not raw addresses, which move with every game patch and would splinter one bug into a different value per game version. A game address with no ID would contribute a version-specific offset, so instead of emitting a value that quietly means something different on each machine, the signature is withheld and says why. A crash inside a plugin hashes as `module+offset` and needs no database at all. The exact tokens hashed are printed in `ANALYSIS`, so the value can be reproduced rather than trusted
- **Stack trace** with symbol names and source locations (when PDB is present)
- **Stack scan** — linearly scans raw stack memory for return addresses and object pointers, recovering the deeper frames the strict frame-pointer unwinder drops in optimised engine code (no external tooling needed)
- **Register dump** (RAX–R15, RIP, EFLAGS) plus **register targets** — each register annotated with `module+offset` (code) or its RTTI type (live game object)
- **RTTI object identification** — resolves pointer-sized values to C++ type names via the game's RTTI metadata
- **Minidump** (`.dmp`) compatible with WinDbg / Visual Studio
- **Module list** with base addresses, sizes, and version strings; SFSE plugins flagged separately
- **Content load order** — the `.esm`/`.esp`/`.esl` plugins from `Plugins.txt`, in load order, with disabled entries marked. The module list above only covers loaded DLLs, so this is what answers "which *content* mod was active". The bracketed index is a position in the load order, not a FormID mod index — base-game masters are implicit and never appear in `Plugins.txt`. Read once at plugin load (nothing touches the filesystem on the crash path); if `Plugins.txt` isn't found, the report says where it looked
- **System & environment** — OS build, CPU, GPU, and memory *as it stood at the fault*: physical RAM and the system commit charge, plus the process's own private commit and working set, so a crash caused by commit exhaustion reads off the log instead of being inferred. Detects **Wine/Proton** via `ntdll!wine_get_version` and names the host kernel — which matters because a raw `__fastfail` is only recoverable from the Wine log, so the report now states up front which environment produced it. OS/CPU/GPU are captured at plugin load; memory is sampled on the crash path, and stays meaningful even for a crash that precedes plugin load
- **Startup log** — appends a timestamped line to `CrashLogger.log` every game launch so you can confirm the plugin is active

All analysis runs inside the plugin at crash time — the `.log` is self-contained and readable without symbols, WinDbg, or any post-processing script.

## Crash log location

```
%USERPROFILE%\Documents\My Games\Starfield\SFSE\Crashlogs\
```

| File | Contents |
|------|----------|
| `CrashLogger.log` | One line per game session — confirms the plugin loaded |
| `CrashLogger_trace.log` | Rolling early-warning trace (first-chance exceptions + lifecycle), flushed as it happens — the only survivor when a crash produces no dump. Rotated to `.old` past 4 MiB |
| `crash_<timestamp>.log` | Full crash report (exception, breadcrumbs, registers, stack, modules) |
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
