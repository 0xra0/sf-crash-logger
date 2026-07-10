#pragma once

// -----------------------------------------------------------------------------
// SystemInfo — the machine the crash happened on: OS, CPU, GPU, memory, and
// whether the game is running under Wine/Proton rather than native Windows.
//
// Split by lifetime. The static facts never change, so they are captured once at
// plugin load and merely read back on the crash path. Memory is the exception:
// exhaustion *causes* crashes, so only its value at the moment of the fault says
// anything useful — it is sampled fresh, and stays meaningful even for a crash
// that preceded Init().
//
// Wine detection matters here because a raw __fastfail cannot be caught in
// process, and the answer for those is the Wine/Proton log rather than anything
// this plugin can produce. A report that does not say which of the two it is
// leaves the reader guessing.
// -----------------------------------------------------------------------------

namespace SystemInfo
{
    // Capture the static facts. Call once at plugin load. Never throws.
    void Init();

    // True once Init() has run; a crash during preload beats it to it.
    bool Available();

    // Cached at Init(); empty until then.
    const std::string& OS();
    const std::string& CPU();
    const std::string& GPU();

    // Non-empty only under Wine/Proton, e.g. "9.0 (host: Linux 6.8.0) — Steam
    // Proton". Empty means native Windows, which is a real answer, not a failure.
    const std::string& Wine();

    // Sampled on every call, not cached. Safe on the crash path.
    std::string SystemMemory();   // physical + system commit charge
    std::string ProcessMemory();  // this process's private commit + working set
}
