#pragma once

#include "CrashContext.h"

// -----------------------------------------------------------------------------
// Breadcrumbs — an early-warning trace that is written *before* a crash and is
// durable even when the full crash handler cannot run.
//
// Some crashes leave no .dmp and no crash_<ts>.log at all: fail-fast /
// heap-corruption trips that bypass SetUnhandledExceptionFilter, and hard
// TerminateProcess kills (GPU device-removed, etc.) that raise no exception. For
// those, the only surviving evidence is whatever we already flushed to disk.
// (Stack overflows used to belong on that list; CrashHandler now reports them
// from a thread that still has a stack.)
//
// This module keeps a continuously-appended trace log using raw WriteFile (so
// data lands in the OS file cache and survives process death, unlike an
// ofstream's process-side buffer) and an allocation-free formatting path (so it
// works even on a corrupted heap). It also logs every interesting first-chance
// exception via a VEH — the cascade that usually precedes the fatal one.
// -----------------------------------------------------------------------------

namespace Breadcrumbs
{
    // Open the trace log, install the first-chance exception logger, and ask for a
    // stack guarantee. Call once, as early as possible (PRELOAD).
    void Init();

    // Append one printf-style line to the trace log. Allocation-free and safe to
    // call from any thread, including from inside an exception handler — but NOT
    // on a thread that has just overflowed its stack, where the line buffer alone
    // does not fit. See CrashHandler for how that case is handled.
    void Log(const char* fmt, ...);

    // Minimal, allocation-free fatal record, flushed to disk immediately. Called
    // first thing inside the crash handler so we always leave *something* even if
    // the rich log writer itself faults. Takes the crash context rather than the
    // raw pointers because it may run on the reporter thread, and the record must
    // still name the thread that crashed.
    void LogFatal(const CrashContext& crash);

    // The most recent breadcrumbs (oldest first), for embedding in the full crash
    // log. Allocates — only call from the best-effort crash path.
    std::vector<std::string> Recent();
}
