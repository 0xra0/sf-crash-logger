#include "PCH.h"
#include "ThreadInfo.h"

namespace ThreadInfo
{
    // The MS_VC_EXCEPTION handshake: raised by a thread to tell an attached
    // debugger its own name. ExceptionInformation is {type, name, tid, flags}.
    static constexpr DWORD       kThreadNameException = 0x406D1388;
    static constexpr ULONG_PTR   kThreadNameType      = 0x1000;
    static constexpr std::size_t kMaxNames            = 64;
    static constexpr std::size_t kNameLen             = 32;

    struct Entry
    {
        std::atomic<std::uint32_t> tid;              // 0 until name[] is fully written
        char                       name[kNameLen]{};
    };

    static Entry                    s_names[kMaxNames]{};
    static std::atomic<std::size_t> s_nameCount{ 0 };
    static std::uint32_t            s_mainThreadId = 0;

    // ---------------------------------------------------------------- name table

    // Called from the VEH: no allocation, no locks, bounded work.
    static void Remember(std::uint32_t tid, const char* name) noexcept
    {
        if (tid == 0 || !name || !*name)
            return;

        const auto used = std::min(s_nameCount.load(std::memory_order_acquire), kMaxNames);
        for (std::size_t i = 0; i < used; ++i)
            if (s_names[i].tid.load(std::memory_order_acquire) == tid)
                return;   // first name wins; a rename tells us nothing new

        const auto slot = s_nameCount.fetch_add(1, std::memory_order_acq_rel);
        if (slot >= kMaxNames)
            return;       // table full: names are a nicety, never a failure

        std::size_t i = 0;
        for (; i + 1 < kNameLen && name[i]; ++i)
            s_names[slot].name[i] = name[i];
        s_names[slot].name[i] = '\0';

        // Publish last: a reader that sees the tid is guaranteed the name behind it.
        s_names[slot].tid.store(tid, std::memory_order_release);
    }

    static std::string Legacy(std::uint32_t tid)
    {
        const auto used = std::min(s_nameCount.load(std::memory_order_acquire), kMaxNames);
        for (std::size_t i = 0; i < used; ++i)
            if (s_names[i].tid.load(std::memory_order_acquire) == tid)
                return std::string(s_names[i].name);
        return {};
    }

    // ---------------------------------------------------------------- VEH

    // Observe-only. Always continues the search; never swallows or alters dispatch.
    // The name pointer belongs to the raising thread, so reading it is guarded.
    static LONG WINAPI ThreadNameWatcher(EXCEPTION_POINTERS* ep) noexcept
    {
        __try {
            const auto* r = ep->ExceptionRecord;
            if (r->ExceptionCode == kThreadNameException &&
                r->NumberParameters >= 4 &&
                r->ExceptionInformation[0] == kThreadNameType) {

                const auto* name = reinterpret_cast<const char*>(r->ExceptionInformation[1]);
                auto        tid  = static_cast<std::uint32_t>(r->ExceptionInformation[2]);
                if (tid == 0xFFFFFFFFu)   // the documented "this thread" sentinel
                    tid = GetCurrentThreadId();
                Remember(tid, name);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // A malformed record is not worth a crash inside the crash logger.
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // ---------------------------------------------------------------- modern name

    static std::string NarrowW(const wchar_t* w)
    {
        if (!w || !*w)
            return {};
        const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
        if (n <= 1)
            return {};
        std::string s(static_cast<std::size_t>(n - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
        return s;
    }

    // GetThreadDescription is Windows 10 1607+; resolve it dynamically so an older
    // host (or a Wine build without it) simply falls through to the legacy table.
    static std::string Modern(std::uint32_t tid)
    {
        if (tid != GetCurrentThreadId())
            return {};   // only the running thread is cheap and safe to ask

        auto* k32 = GetModuleHandleW(L"kernel32.dll");
        if (!k32)
            return {};

        using GetThreadDescriptionFn = HRESULT(WINAPI*)(HANDLE, PWSTR*);
        auto fn = reinterpret_cast<GetThreadDescriptionFn>(GetProcAddress(k32, "GetThreadDescription"));
        if (!fn)
            return {};

        PWSTR desc = nullptr;
        if (FAILED(fn(GetCurrentThread(), &desc)) || !desc)
            return {};

        std::string out = NarrowW(desc);
        LocalFree(desc);
        return out;
    }

    // ---------------------------------------------------------------- interface

    void Init()
    {
        s_mainThreadId = GetCurrentThreadId();
        AddVectoredExceptionHandler(0, ThreadNameWatcher);   // last: we only observe
    }

    std::uint32_t MainThreadId()
    {
        return s_mainThreadId;
    }

    bool IsMainThread(std::uint32_t tid)
    {
        return s_mainThreadId != 0 && tid == s_mainThreadId;
    }

    std::string Describe(std::uint32_t tid)
    {
        std::string name = Modern(tid);
        if (name.empty())
            name = Legacy(tid);

        const char* role = (s_mainThreadId == 0) ? "main thread unknown"
                         : IsMainThread(tid)     ? "main thread"
                                                 : "not the main thread";

        if (name.empty())
            return std::format("{} ({})", tid, role);
        return std::format("{} \"{}\" ({})", tid, name, role);
    }
}
