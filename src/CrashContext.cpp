#include "PCH.h"
#include "CrashContext.h"

namespace
{
    using GetCurrentThreadStackLimits_t = void(WINAPI*)(PULONG_PTR, PULONG_PTR);

    // Resolved once at install time. Capture() runs on a thread that may have a
    // few hundred bytes of stack left, which is no place for a GetProcAddress.
    GetCurrentThreadStackLimits_t g_getStackLimits = nullptr;
}

void CrashContext::Init() noexcept
{
    if (auto* k32 = GetModuleHandleW(L"kernel32.dll"))
        g_getStackLimits = reinterpret_cast<GetCurrentThreadStackLimits_t>(
            GetProcAddress(k32, "GetCurrentThreadStackLimits"));   // Win8+
}

CrashContext CrashContext::Capture(EXCEPTION_POINTERS* ep) noexcept
{
    CrashContext c;
    c.ep       = ep;
    c.threadId = GetCurrentThreadId();

    if (g_getStackLimits) {
        ULONG_PTR low = 0, high = 0;
        g_getStackLimits(&low, &high);
        if (high > low) {
            c.stackLow  = low;
            c.stackHigh = high;
        }
    }
    return c;
}
