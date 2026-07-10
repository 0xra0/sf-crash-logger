#pragma once

// -----------------------------------------------------------------------------
// ThreadInfo — which thread faulted, and what it is called.
//
// A null dereference on a worker thread and the same one on the main thread are
// different bugs with different culprits, and the report never said which it was.
//
// Thread names come from two places, because engines use two conventions:
//
//   * SetThreadDescription (Windows 10+), read back with GetThreadDescription.
//   * The older MS_VC_EXCEPTION (0x406D1388) debugger handshake, which is not an
//     API at all — it is a first-chance exception carrying the name, addressed to
//     a debugger that may not exist. The only way to see it is to watch every
//     exception, so we register an observe-only VEH and remember what it says.
//
// The name table is fixed-size and allocation-free: the VEH runs for every
// exception in the process, including ones raised on a corrupted heap.
// -----------------------------------------------------------------------------

namespace ThreadInfo
{
    // Capture the main thread and start watching for thread names. Call once at
    // SFSE preload, which runs on the game's main thread. Never throws.
    void Init();

    // The thread Init() ran on. Zero if Init() never ran.
    std::uint32_t MainThreadId();

    bool IsMainThread(std::uint32_t tid);

    // e.g. `4812 "TaskThread 3" (not the main thread)`, or `1234 (main thread)`
    // when the thread has no name. Safe to call on the crash path.
    std::string Describe(std::uint32_t tid);
}
