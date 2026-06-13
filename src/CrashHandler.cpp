#include "PCH.h"
#include "CrashHandler.h"
#include "LogWriter.h"
#include "Modules.h"
#include "RTTIReader.h"
#include "StackWalker.h"

namespace CrashHandler
{
    static LPTOP_LEVEL_EXCEPTION_FILTER s_previousFilter = nullptr;
    static std::atomic_bool             s_handled{ false };

    // -------------------------------------------------------------------------
    // Exception codes that represent genuine, fatal crashes.
    // Used by the VEH to avoid logging first-chance exceptions that game code
    // catches normally (e.g. C++ throw, scripting faults).
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

    // -------------------------------------------------------------------------
    // Core crash handler — called by both the SEH filter and the VEH fallback.
    // The atomic flag ensures we only write one log even if both fire.
    // -------------------------------------------------------------------------
    static void ProcessCrash(EXCEPTION_POINTERS* ep)
    {
        if (s_handled.exchange(true))
            return;

        __try {
            const auto timestamp = LogWriter::MakeFileTimestamp();
            const auto logDir    = LogWriter::GetLogDir();

            auto modules     = Modules::GetAll();
            auto frames      = StackWalker::Walk(ep->ContextRecord);
            auto rttiObjects = RTTIReader::IdentifyRegisters(ep->ContextRecord);

            LogWriter::Write(ep, frames, modules, rttiObjects, timestamp);
            LogWriter::WriteMiniDump(ep, logDir, timestamp);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            REX::ERROR("CrashHandler: secondary exception while writing crash log.");
        }
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
    // VEH fallback — catches crashes if another plugin replaces our SEH filter
    // after we installed it (and our IAT patch doesn't cover that path).
    // Only fires for codes that are never legitimately caught by game code.
    // -------------------------------------------------------------------------
    static LONG WINAPI VEHFallback(EXCEPTION_POINTERS* ep)
    {
        // Only intervene for clear crash codes on non-continuable exceptions.
        // This avoids false positives from first-chance exceptions that the
        // engine handles itself (e.g. Papyrus VM faults, script exceptions).
        const auto flags = ep->ExceptionRecord->ExceptionFlags;
        const auto code  = ep->ExceptionRecord->ExceptionCode;

        if (!IsCrashCode(code) || !(flags & EXCEPTION_NONCONTINUABLE))
            return EXCEPTION_CONTINUE_SEARCH;

        ProcessCrash(ep);
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
    // Patch the IAT entry for SetUnhandledExceptionFilter inside a single module.
    // Checks both "KERNEL32.DLL" and "kernelbase.dll" import names.
    // -------------------------------------------------------------------------
    static void PatchModuleIAT(HMODULE hModule)
    {
        auto* base = reinterpret_cast<std::uint8_t*>(hModule);

        __try {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return;

            auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (dir.VirtualAddress == 0)
                return;

            auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
            for (; desc->Name; ++desc) {
                auto* dllName = reinterpret_cast<const char*>(base + desc->Name);

                // SetUnhandledExceptionFilter may be imported from either name
                if (_stricmp(dllName, "KERNEL32.DLL") != 0 &&
                    _stricmp(dllName, "kernelbase.dll") != 0)
                    continue;

                auto* origThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->OriginalFirstThunk);
                auto* thunk     = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->FirstThunk);

                for (; origThunk->u1.Function; ++origThunk, ++thunk) {
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                        continue;

                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        base + origThunk->u1.AddressOfData);
                    if (_stricmp(ibn->Name, "SetUnhandledExceptionFilter") != 0)
                        continue;

                    // Found the IAT slot — overwrite it with our stub
                    DWORD oldProtect = 0;
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = reinterpret_cast<ULONGLONG>(&StubSetUnhandledExceptionFilter);
                    VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                    return;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    static BOOL CALLBACK PatchAllIATsCallback(PCSTR, DWORD64 moduleBase, ULONG, PVOID)
    {
        PatchModuleIAT(reinterpret_cast<HMODULE>(moduleBase));
        return TRUE;
    }

    // -------------------------------------------------------------------------

    void Install()
    {
        // 1. VEH fallback (registered first, cannot be removed by other plugins)
        AddVectoredExceptionHandler(1, VEHFallback);

        // 2. Primary SEH filter
        s_previousFilter = SetUnhandledExceptionFilter(SEHFilter);

        // 3. Patch SetUnhandledExceptionFilter in every currently-loaded module's IAT
        //    so future calls from those modules are silently blocked.
        EnumerateLoadedModulesA64(GetCurrentProcess(), PatchAllIATsCallback, nullptr);

        REX::INFO("CrashHandler installed (SEH filter + VEH fallback + {} IAT patches).",
            "all loaded modules");
    }
}
