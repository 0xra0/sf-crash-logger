#include "PCH.h"
#include "Breadcrumbs.h"
#include "LogWriter.h"   // GetLogDir()

#include <cstdarg>
#include <cstdio>

namespace Breadcrumbs
{
    // --- tunables -----------------------------------------------------------
    static constexpr std::size_t kLineMax        = 512;   // one formatted record
    static constexpr std::size_t kRingCount      = 32;    // recent lines kept in RAM
    static constexpr std::uint32_t kMaxFirstChance = 2000; // cap noisy sessions

    // --- state --------------------------------------------------------------
    static HANDLE           s_file = INVALID_HANDLE_VALUE;
    static CRITICAL_SECTION s_ringLock;
    static bool             s_ringLockInit = false;

    // Fixed-size ring of the most recent breadcrumb lines. Allocation-free so it
    // can be updated from inside an exception handler.
    static char        s_ring[kRingCount][kLineMax];
    static std::size_t s_ringHead  = 0;   // next slot to write
    static std::size_t s_ringFill  = 0;   // number of valid slots

    // First-chance de-dup / rate-limit (best-effort; minor races are harmless).
    static std::atomic<std::uint64_t> s_lastFirstChanceKey{ 0 };
    static std::atomic<std::uint32_t> s_firstChanceCount{ 0 };

    // ------------------------------------------------------------------------
    static const char* CodeName(DWORD code) noexcept
    {
        switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:         return "ACCESS_VIOLATION";
        case EXCEPTION_IN_PAGE_ERROR:            return "IN_PAGE_ERROR";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_DATATYPE_MISALIGNMENT:    return "DATATYPE_MISALIGNMENT";
        case EXCEPTION_ILLEGAL_INSTRUCTION:      return "ILLEGAL_INSTRUCTION";
        case EXCEPTION_PRIV_INSTRUCTION:         return "PRIV_INSTRUCTION";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "INT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_STACK_OVERFLOW:           return "STACK_OVERFLOW";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "NONCONTINUABLE";
        case 0xC0000374:                         return "HEAP_CORRUPTION";
        case 0xC0000409:                         return "STACK_BUFFER_OVERRUN";  // __fastfail / /GS
        case 0xC000041D:                         return "FATAL_USER_CALLBACK";
        default:                                 return "EXCEPTION";
        }
    }

    // Codes worth a breadcrumb. We deliberately skip the high-volume, benign
    // first-chance traffic games generate: C++ EH (0xE06D7363), OutputDebugString
    // (0x40010006), SetThreadName (0x406D1388), breakpoints and single-steps.
    static bool IsInteresting(DWORD code) noexcept
    {
        switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_IN_PAGE_ERROR:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        case EXCEPTION_DATATYPE_MISALIGNMENT:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_PRIV_INSTRUCTION:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        case 0xC0000374:   // heap corruption
        case 0xC0000409:   // stack buffer overrun / __fastfail
        case 0xC000041D:   // fatal user-callback
            return true;
        default:
            return false;
        }
    }

    // Store a completed line in the in-RAM ring (for embedding in the crash log).
    static void PushRing(const char* line) noexcept
    {
        if (!s_ringLockInit)
            return;
        EnterCriticalSection(&s_ringLock);
        std::size_t n = 0;
        char* dst = s_ring[s_ringHead];
        for (; n < kLineMax - 1 && line[n]; ++n)
            dst[n] = line[n];
        dst[n]     = '\0';
        s_ringHead = (s_ringHead + 1) % kRingCount;
        if (s_ringFill < kRingCount)
            ++s_ringFill;
        LeaveCriticalSection(&s_ringLock);
    }

    // Format "[HH:MM:SS.mmm|t<tid>] <msg>\n" into buf without touching the heap.
    static int FormatLine(char* buf, std::size_t cap, const char* fmt, va_list ap) noexcept
    {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        const int pre = std::snprintf(buf, cap, "[%02u:%02u:%02u.%03u|t%lu] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            static_cast<unsigned long>(GetCurrentThreadId()));
        if (pre < 0 || static_cast<std::size_t>(pre) >= cap)
            return pre < 0 ? pre : static_cast<int>(cap) - 1;

        int body = std::vsnprintf(buf + pre, cap - pre, fmt, ap);
        if (body < 0)
            body = 0;

        std::size_t len = pre + body;
        if (len >= cap - 1)
            len = cap - 2;
        buf[len]     = '\n';
        buf[len + 1] = '\0';
        return static_cast<int>(len + 1);
    }

    // ------------------------------------------------------------------------
    void Log(const char* fmt, ...)
    {
        char buf[kLineMax];

        va_list ap;
        va_start(ap, fmt);
        const int len = FormatLine(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (len <= 0)
            return;

        // Atomic append: opened with FILE_APPEND_DATA, so concurrent writers each
        // land at end-of-file without interleaving records. No lock needed.
        if (s_file != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(s_file, buf, static_cast<DWORD>(len), &written, nullptr);
        }

        PushRing(buf);
    }

    void LogFatal(EXCEPTION_POINTERS* ep)
    {
        if (!ep || !ep->ExceptionRecord)
            return;

        const auto* r     = ep->ExceptionRecord;
        const DWORD code  = r->ExceptionCode;
        const auto  addr  = reinterpret_cast<std::uint64_t>(r->ExceptionAddress);

        std::uint64_t fault = 0;
        if (r->NumberParameters >= 2 &&
            (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR))
            fault = r->ExceptionInformation[1];

        // Pure, loader-lock-free path: no module resolution here (that stays in
        // the rich writer). Just the raw facts, then force to physical disk.
        Log("FATAL %s (0x%08lX) at 0x%016llX faultaddr=0x%016llX",
            CodeName(code), static_cast<unsigned long>(code),
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(fault));

        if (s_file != INVALID_HANDLE_VALUE)
            FlushFileBuffers(s_file);
    }

    std::vector<std::string> Recent()
    {
        std::vector<std::string> out;
        if (!s_ringLockInit)
            return out;

        EnterCriticalSection(&s_ringLock);
        const std::size_t start = (s_ringFill < kRingCount) ? 0 : s_ringHead;
        for (std::size_t i = 0; i < s_ringFill; ++i) {
            const char* line = s_ring[(start + i) % kRingCount];
            std::string s(line);
            if (!s.empty() && s.back() == '\n')
                s.pop_back();
            out.emplace_back(std::move(s));
        }
        LeaveCriticalSection(&s_ringLock);
        return out;
    }

    // ------------------------------------------------------------------------
    // First-chance exception logger. Runs for *every* exception in the process,
    // before any SEH handler gets it — this is the "early hint" trail. Registered
    // last (priority 0) so the crash-catching VEH still runs first. Always
    // continues the search; it never swallows or alters dispatch.
    // ------------------------------------------------------------------------
    static LONG WINAPI FirstChanceLogger(EXCEPTION_POINTERS* ep)
    {
        __try {
            const auto* r    = ep->ExceptionRecord;
            const DWORD code = r->ExceptionCode;
            if (!IsInteresting(code))
                return EXCEPTION_CONTINUE_SEARCH;

            const auto addr = reinterpret_cast<std::uint64_t>(r->ExceptionAddress);

            // Collapse repeats of the same code+address (tight fault loops).
            const std::uint64_t key = (static_cast<std::uint64_t>(code) << 48) ^ addr;
            if (s_lastFirstChanceKey.exchange(key) == key)
                return EXCEPTION_CONTINUE_SEARCH;

            if (s_firstChanceCount.fetch_add(1) >= kMaxFirstChance)
                return EXCEPTION_CONTINUE_SEARCH;

            std::uint64_t fault = 0;
            if (r->NumberParameters >= 2 &&
                (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR))
                fault = r->ExceptionInformation[1];

            Log("first-chance %s (0x%08lX) at 0x%016llX faultaddr=0x%016llX",
                CodeName(code), static_cast<unsigned long>(code),
                static_cast<unsigned long long>(addr),
                static_cast<unsigned long long>(fault));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Never let the logger itself perturb dispatch.
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // ------------------------------------------------------------------------
    void Init()
    {
        InitializeCriticalSection(&s_ringLock);
        s_ringLockInit = true;

        // Reserve stack so the SEH filter can still run on a stack-overflow crash.
        ULONG guarantee = 64 * 1024;
        SetThreadStackGuarantee(&guarantee);

        std::error_code ec;
        const auto dir = LogWriter::GetLogDir();
        std::filesystem::create_directories(dir, ec);
        const auto path = dir / "CrashLogger_trace.log";

        // Append across sessions (a silent-death crash leaves its trail for the
        // relaunch to preserve). FILE_APPEND_DATA gives atomic multi-thread
        // appends; buffered WriteFile is OS-cache-durable across process death.
        s_file = CreateFileW(
            path.wstring().c_str(),
            FILE_APPEND_DATA | SYNCHRONIZE,
            FILE_SHARE_READ,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        // Register the first-chance trail last so the crash-catching VEH wins.
        AddVectoredExceptionHandler(0, FirstChanceLogger);

        Log("==== session start (pid %lu) ====", static_cast<unsigned long>(GetCurrentProcessId()));
        if (s_file != INVALID_HANDLE_VALUE)
            FlushFileBuffers(s_file);
    }
}
