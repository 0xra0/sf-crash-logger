#include "PCH.h"
#include "CrashHandler.h"
#include "Breadcrumbs.h"
#include "LogWriter.h"
#include "Modules.h"
#include "RTTIReader.h"
#include "StackWalker.h"

#include <cstdlib>
#include <exception>

namespace CrashHandler
{
    static LPTOP_LEVEL_EXCEPTION_FILTER s_previousFilter = nullptr;
    static std::atomic_bool             s_handled{ false };
    static std::atomic_bool             s_hijackLogged{ false };
    static HMODULE                      s_selfModule = nullptr;
    static void*                        s_ldrCookie  = nullptr;

    // The system DLLs whose exports we hook. We never patch *their* IATs: the
    // hooks exist to intercept other modules (plugins, overlays, ASI loaders)
    // calling these functions, and on platforms where one system DLL reaches
    // another through an IAT jump-thunk (e.g. kernel32!TerminateProcess forwarding
    // to kernelbase on Wine), patching that internal slot would send our stub's own
    // forward call — made through the real export — straight back into the stub.
    static HMODULE s_systemModules[3] = {};

    // Real entry points behind our IAT stubs, resolved once at install time so
    // the stubs can still perform the actual operation after logging. We must call
    // through these rather than the plain import names: our own IAT would otherwise
    // route us straight back into our own stubs.
    using RaiseFailFastException_t      = void (WINAPI*)(PEXCEPTION_RECORD, PCONTEXT, DWORD);
    using TerminateProcess_t            = BOOL (WINAPI*)(HANDLE, UINT);
    using ExitProcess_t                 = void (WINAPI*)(UINT);
    using SetUnhandledExceptionFilter_t = LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI*)(LPTOP_LEVEL_EXCEPTION_FILTER);

    static RaiseFailFastException_t      s_realRaiseFailFast    = nullptr;
    static TerminateProcess_t            s_realTerminateProcess = nullptr;
    static ExitProcess_t                 s_realExitProcess      = nullptr;
    static SetUnhandledExceptionFilter_t s_realSetFilter        = nullptr;
    static std::terminate_handler        s_prevTerminate        = nullptr;

    // -------------------------------------------------------------------------
    // Exception codes that represent genuine, fatal crashes.
    // -------------------------------------------------------------------------
    static bool IsCrashCode(DWORD code) noexcept
    {
        switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        case EXCEPTION_DATATYPE_MISALIGNMENT:
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        case EXCEPTION_FLT_STACK_CHECK:
        case EXCEPTION_FLT_OVERFLOW:
        case EXCEPTION_FLT_UNDERFLOW:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_IN_PAGE_ERROR:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_PRIV_INSTRUCTION:
        case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            return true;
        default:
            return false;
        }
    }

    // A function containing __try may not also contain objects that require
    // unwinding: MSVC rejects it outright (C2712) and clang miscompiles it under
    // /EHa. The report writer owns vectors and paths, so it lives in its own frame
    // and ProcessCrash guards only the call. Same for the failure log, whose
    // formatting builds temporaries.
    __declspec(noinline) static void WriteFullReport(EXCEPTION_POINTERS* ep)
    {
        const auto timestamp = LogWriter::MakeFileTimestamp();
        const auto logDir    = LogWriter::GetLogDir();

        auto modules = Modules::GetAll();
        auto frames  = StackWalker::Walk(ep->ContextRecord);
        auto scanned = StackWalker::ScanStack(ep->ContextRecord);

        LogWriter::Write(ep, frames, scanned, modules, timestamp);
        LogWriter::WriteMiniDump(ep, logDir, timestamp);
    }

    __declspec(noinline) static void ReportSecondaryFailure()
    {
        REX::ERROR("CrashHandler: secondary exception while writing crash log.");
    }

    // -------------------------------------------------------------------------
    // Core crash handler — the single place a report is produced.
    // The atomic flag ensures we only write one log even if several paths fire.
    // -------------------------------------------------------------------------
    static void ProcessCrash(EXCEPTION_POINTERS* ep)
    {
        if (s_handled.exchange(true))
            return;

        // Guaranteed, allocation-free record first — flushed to disk before the
        // rich writer runs, so we leave evidence even if that writer itself faults
        // (e.g. on a corrupted heap).
        Breadcrumbs::LogFatal(ep);

        __try {
            WriteFullReport(ep);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ReportSecondaryFailure();
        }
    }

    // -------------------------------------------------------------------------
    // Report a crash for which the OS never handed us EXCEPTION_POINTERS (a
    // fail-fast, a self-TerminateProcess, or std::terminate). We synthesise the
    // record/context from the current call site so the same pipeline produces a
    // full .log and .dmp captured at the point the process is dying.
    // -------------------------------------------------------------------------
    static void ReportSynthetic(DWORD code, PEXCEPTION_RECORD rec, PCONTEXT ctx)
    {
        CONTEXT          localCtx{};
        EXCEPTION_RECORD localRec{};

        if (!ctx) {
            RtlCaptureContext(&localCtx);
            ctx = &localCtx;
        }
        if (!rec) {
            localRec.ExceptionCode    = code;
            localRec.ExceptionFlags   = EXCEPTION_NONCONTINUABLE;
            localRec.ExceptionAddress = reinterpret_cast<PVOID>(ctx->Rip);
            rec = &localRec;
        }

        EXCEPTION_POINTERS ep{ rec, ctx };
        ProcessCrash(&ep);
    }

    // -------------------------------------------------------------------------
    // Termination / fail-fast backstop stubs (installed into module IATs).
    //
    // These catch the abnormal-exit paths that BYPASS the SEH filter:
    // RaiseFailFastException, an engine self-TerminateProcess, and std::terminate.
    // NOTE: a raw compiler __fastfail / int 29h (a smashed /GS stack cookie or a
    // heap-manager corruption trip) still cannot be caught in-process by design —
    // for those the Wine/Proton log (PROTON_LOG=1) remains the source of truth.
    // -------------------------------------------------------------------------
    static void WINAPI StubRaiseFailFastException(PEXCEPTION_RECORD rec, PCONTEXT ctx, DWORD flags)
    {
        Breadcrumbs::Log("RaiseFailFastException (flags=0x%lX) — fail-fast, capturing stack",
            static_cast<unsigned long>(flags));
        ReportSynthetic(rec ? rec->ExceptionCode : 0xC0000602 /*STATUS_FAIL_FAST_EXCEPTION*/, rec, ctx);

        if (s_realRaiseFailFast)
            s_realRaiseFailFast(rec, ctx, flags);   // never returns
        if (s_realTerminateProcess)                 // ... but be certain we die
            s_realTerminateProcess(GetCurrentProcess(), rec ? rec->ExceptionCode : 0xC0000602);
    }

    static BOOL WINAPI StubTerminateProcess(HANDLE hProcess, UINT code)
    {
        const bool self = hProcess == GetCurrentProcess() ||
                          GetProcessId(hProcess) == GetCurrentProcessId();
        if (self) {
            Breadcrumbs::Log("TerminateProcess(self, code=0x%X)", code);
            // A code of 0 is a normal fast-exit (skip destructors); only capture a
            // full report for abnormal (non-zero) self-termination.
            if (code != 0)
                ReportSynthetic(0xE0000001 /*synthetic: self-terminate*/, nullptr, nullptr);
        }
        return s_realTerminateProcess ? s_realTerminateProcess(hProcess, code) : FALSE;
    }

    static void WINAPI StubExitProcess(UINT code)
    {
        // Clean-exit path — a breadcrumb only, no crash report (avoids false
        // positives when the player simply quits the game).
        Breadcrumbs::Log("ExitProcess(code=0x%X)", code);
        if (s_realExitProcess)
            s_realExitProcess(code);   // never returns
    }

    // std::terminate — unhandled C++ exception or a noexcept violation.
    static void OnTerminate()
    {
        Breadcrumbs::Log("std::terminate — unhandled C++ exception / noexcept violation");
        ReportSynthetic(0xE0000002 /*synthetic: std::terminate*/, nullptr, nullptr);
        if (s_prevTerminate)
            s_prevTerminate();
        std::abort();
    }

    // -------------------------------------------------------------------------
    // Primary handler — registered via SetUnhandledExceptionFilter.
    // Only called for genuinely unhandled exceptions (safe from false positives).
    // -------------------------------------------------------------------------
    static LONG WINAPI SEHFilter(EXCEPTION_POINTERS* ep)
    {
        ProcessCrash(ep);

        if (s_previousFilter)
            return s_previousFilter(ep);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // -------------------------------------------------------------------------
    // Re-arm our top-level filter. Writing it is a single interlocked pointer
    // exchange, so there is never a window with no filter installed; calling this
    // when ours is already current is a no-op that returns our own address.
    //
    // Whoever displaced us does not get chained to: that matches
    // StubSetUnhandledExceptionFilter, which has always silently refused
    // replacement. Chaining would also risk unbounded recursion, since the stub
    // hands callers SEHFilter back as their "previous" filter.
    // -------------------------------------------------------------------------
    static void EnsureTopLevelFilter() noexcept
    {
        if (!s_realSetFilter)
            return;

        const auto prev = s_realSetFilter(&SEHFilter);
        if (prev != &SEHFilter && !s_hijackLogged.exchange(true))
            Breadcrumbs::Log("top-level exception filter had been replaced (0x%p) — re-armed ours",
                reinterpret_cast<void*>(prev));
    }

    // -------------------------------------------------------------------------
    // VEH filter guard — runs first-chance, before any frame-based handler.
    //
    // A vectored handler CANNOT tell whether an exception is about to be handled:
    // hardware faults (access violation, divide-by-zero, stack overflow) are all
    // dispatched first-chance and *continuable*, so any attempt to classify them
    // here either reports crashes the game would have recovered from, or — as with
    // the EXCEPTION_NONCONTINUABLE test this replaces — reports nothing at all.
    //
    // So we do not report from here. Instead we make sure our top-level filter is
    // still installed. UnhandledExceptionFilter is reached from the SEH frame at
    // the base of the thread, which is searched *after* vectored handlers in this
    // same dispatch — so re-arming now means a genuinely unhandled exception still
    // lands in SEHFilter on this very fault, while one that a frame handler catches
    // produces no report. That yields the intended backstop with no false positives.
    // -------------------------------------------------------------------------
    static LONG WINAPI VEHFilterGuard(EXCEPTION_POINTERS* ep)
    {
        if (IsCrashCode(ep->ExceptionRecord->ExceptionCode))
            EnsureTopLevelFilter();

        return EXCEPTION_CONTINUE_SEARCH;
    }

    // -------------------------------------------------------------------------
    // IAT hook stub — replaces SetUnhandledExceptionFilter in all module IATs.
    // Silently ignores replacement attempts; returns our filter so callers that
    // save the return value still chain to something meaningful.
    // -------------------------------------------------------------------------
    static LPTOP_LEVEL_EXCEPTION_FILTER WINAPI StubSetUnhandledExceptionFilter(
        LPTOP_LEVEL_EXCEPTION_FILTER /*lpFilter*/)
    {
        // Do not replace our handler. Return our own filter as the "previous" one
        // so code that chains handlers still ends up calling us.
        return SEHFilter;
    }

    // -------------------------------------------------------------------------
    // Imports we redirect in every module's IAT.
    //
    // Slots are matched by resolved target address rather than by import name.
    // Name matching only works for descriptors that still carry an intact
    // OriginalFirstThunk, and misses modules that import these through an
    // api-ms-win-*.dll apiset stub or by ordinal. Address matching covers all
    // three, and is naturally idempotent: an already-patched slot holds our stub,
    // which never equals a resolved target.
    // -------------------------------------------------------------------------
    struct IATHook {
        const char* name;
        void*       stub;
        void*       real[2];   // as exported by kernel32 and by kernelbase
    };

    enum : std::size_t { kHookSetFilter, kHookFailFast, kHookTerminate, kHookExit };

    static IATHook s_iatHooks[] = {
        { "SetUnhandledExceptionFilter", reinterpret_cast<void*>(&StubSetUnhandledExceptionFilter), {} },
        { "RaiseFailFastException",      reinterpret_cast<void*>(&StubRaiseFailFastException),      {} },
        { "TerminateProcess",            reinterpret_cast<void*>(&StubTerminateProcess),            {} },
        { "ExitProcess",                 reinterpret_cast<void*>(&StubExitProcess),                 {} },
    };

    static void ResolveRealImports()
    {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE kb  = GetModuleHandleW(L"kernelbase.dll");

        s_systemModules[0] = k32;
        s_systemModules[1] = kb;
        s_systemModules[2] = GetModuleHandleW(L"ntdll.dll");

        for (auto& hook : s_iatHooks) {
            hook.real[0] = k32 ? reinterpret_cast<void*>(GetProcAddress(k32, hook.name)) : nullptr;
            hook.real[1] = kb ? reinterpret_cast<void*>(GetProcAddress(kb, hook.name)) : nullptr;
            if (hook.real[1] == hook.real[0])
                hook.real[1] = nullptr;   // kernel32 forwards to kernelbase; one address
        }

        // Prefer the kernel32 resolution, falling back to kernelbase.
        auto pick = [](const IATHook& h) { return h.real[0] ? h.real[0] : h.real[1]; };

        s_realSetFilter        = reinterpret_cast<SetUnhandledExceptionFilter_t>(pick(s_iatHooks[kHookSetFilter]));
        s_realRaiseFailFast    = reinterpret_cast<RaiseFailFastException_t>(pick(s_iatHooks[kHookFailFast]));
        s_realTerminateProcess = reinterpret_cast<TerminateProcess_t>(pick(s_iatHooks[kHookTerminate]));
        s_realExitProcess      = reinterpret_cast<ExitProcess_t>(pick(s_iatHooks[kHookExit]));
    }

    // -------------------------------------------------------------------------
    // Point every hooked IAT slot in one module at our stub. Idempotent, so it is
    // safe to run over the whole module list repeatedly.
    // -------------------------------------------------------------------------
    static bool IsSystemModule(HMODULE hModule) noexcept
    {
        for (HMODULE m : s_systemModules)
            if (m && m == hModule)
                return true;
        return false;
    }

    static void PatchModuleIAT(HMODULE hModule)
    {
        // Never patch ourselves: our stubs call the real entry points through the
        // saved pointers, and an unpatched self-IAT keeps that unambiguous.
        // Never patch the hooked system DLLs themselves (see s_systemModules).
        if (!hModule || hModule == s_selfModule || IsSystemModule(hModule))
            return;

        auto* base = reinterpret_cast<std::uint8_t*>(hModule);

        __try {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return;

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return;

            auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (dir.VirtualAddress == 0 || dir.Size == 0)
                return;

            auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
            for (; desc->Name; ++desc) {
                if (desc->FirstThunk == 0)
                    continue;

                // The bound IAT: every slot already holds the address the loader
                // resolved it to, whatever DLL name or ordinal it was written as.
                auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->FirstThunk);
                for (; thunk->u1.Function; ++thunk) {
                    auto* target = reinterpret_cast<void*>(thunk->u1.Function);

                    for (const auto& hook : s_iatHooks) {
                        if (target != hook.real[0] && target != hook.real[1])
                            continue;

                        DWORD oldProtect = 0;
                        if (!VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect))
                            break;
                        thunk->u1.Function = reinterpret_cast<ULONGLONG>(hook.stub);
                        VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                        break;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    static void PatchAllModules()
    {
        HMODULE hMods[1024]{};
        DWORD   cbNeeded = 0;
        if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
            return;

        const DWORD count = (std::min)(static_cast<DWORD>(std::size(hMods)),
                                       static_cast<DWORD>(cbNeeded / sizeof(HMODULE)));
        for (DWORD i = 0; i < count; ++i)
            PatchModuleIAT(hMods[i]);
    }

    // -------------------------------------------------------------------------
    // Loader notification. Install() runs at SFSE preload, when little more than
    // the game executable and the system DLLs are mapped — every SFSE plugin, ASI
    // loader and graphics overlay arrives later and would otherwise keep an
    // unpatched IAT, i.e. exactly the population these hooks exist to contain.
    //
    // ntdll!LdrRegisterDllNotification hands us each new module as it lands (after
    // its imports are snapped and its DllMain has run), which is early enough for
    // the plugin's own SFSE entry points. Undocumented but stable since Vista, and
    // implemented by Wine; we degrade to the post-load rescan if it is missing.
    // -------------------------------------------------------------------------
    struct LdrUnicodeString {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    };

    struct LdrDllNotificationData {
        ULONG                   Flags;
        const LdrUnicodeString* FullDllName;
        const LdrUnicodeString* BaseDllName;
        void*                   DllBase;
        ULONG                   SizeOfImage;
    };

    using LdrDllNotification_t         = void (NTAPI*)(ULONG, const LdrDllNotificationData*, void*);
    using LdrRegisterDllNotification_t = LONG (NTAPI*)(ULONG, LdrDllNotification_t, void*, void**);

    static void NTAPI OnDllLoaded(ULONG reason, const LdrDllNotificationData* data, void*)
    {
        constexpr ULONG kLoaded = 1;

        // Runs under the loader lock: patching touches only VirtualProtect and the
        // module's own IAT pages, so it stays free of allocation and of file I/O.
        if (reason == kLoaded && data && data->DllBase)
            PatchModuleIAT(static_cast<HMODULE>(data->DllBase));
    }

    static bool RegisterDllNotification()
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return false;

        auto reg = reinterpret_cast<LdrRegisterDllNotification_t>(
            GetProcAddress(ntdll, "LdrRegisterDllNotification"));
        if (!reg)
            return false;

        if (reg(0, &OnDllLoaded, nullptr, &s_ldrCookie) < 0) {   // NTSTATUS: negative is failure
            s_ldrCookie = nullptr;
            return false;
        }
        return true;
    }

    // -------------------------------------------------------------------------

    void Install()
    {
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&Install), &s_selfModule);

        // 0. Resolve the real entry points our IAT stubs forward to, and route
        //    std::terminate through our reporter (bypasses the SEH filter otherwise).
        ResolveRealImports();
        s_prevTerminate = std::set_terminate(&OnTerminate);

        // 1. VEH filter guard (registered first, cannot be removed by other plugins)
        AddVectoredExceptionHandler(1, VEHFilterGuard);

        // 2. Primary SEH filter
        s_previousFilter = s_realSetFilter ? s_realSetFilter(&SEHFilter)
                                           : SetUnhandledExceptionFilter(&SEHFilter);

        // 3. Patch the currently-loaded modules, then arrange for everything loaded
        //    from here on to be patched as it arrives.
        PatchAllModules();
        const bool notify = RegisterDllNotification();

        Breadcrumbs::Log("crash handler installed (dll-load notification %s)",
            notify ? "active" : "unavailable — falling back to post-load rescan");

        REX::INFO("CrashHandler installed (SEH filter + VEH filter guard + termination/fail-fast IAT hooks).");
    }

    void OnPostLoad()
    {
        // Catches anything the loader notification missed — and everything, if it
        // could not be registered at all. Both passes are idempotent.
        PatchAllModules();
        EnsureTopLevelFilter();
    }
}
