#pragma once

// -----------------------------------------------------------------------------
// Everything the report needs to know about the thread that actually crashed.
//
// The report is not always written on that thread. A stack overflow leaves under
// 2 KiB of committed stack below RSP — enough to signal another thread, and not
// much else — so that report is produced by a dedicated reporter thread instead
// (see CrashHandler). Nothing downstream may therefore ask a GetCurrent*()
// function about the crash: the answer would describe the reporter, not the
// victim. It is captured here, up front, on the dying thread itself.
// -----------------------------------------------------------------------------

struct CrashContext
{
    EXCEPTION_POINTERS* ep{};
    std::uint32_t       threadId{};

    // The crashing thread's whole reserved stack span, committed or not.
    // Zero when the host is too old to report it (Win8+ only).
    std::uint64_t stackLow{};
    std::uint64_t stackHigh{};

    // Resolve the OS entry points Capture() needs, once, while the stack is
    // healthy. Call from Install().
    static void Init() noexcept;

    // Snapshot the calling thread. Allocation-free, lock-free and a few dozen
    // bytes of stack, so it is safe on a thread that has just overflowed.
    static CrashContext Capture(EXCEPTION_POINTERS* ep) noexcept;
};
