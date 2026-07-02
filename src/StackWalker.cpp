#include "PCH.h"
#include "StackWalker.h"

namespace StackWalker
{
    // DbgHelp is not thread-safe; all calls must be serialized.
    static std::mutex s_dbghelpMutex;

    static std::string ResolveSymbol(HANDLE process, std::uint64_t address, std::uint64_t& outDisplacement)
    {
        alignas(SYMBOL_INFO) char buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
        auto* sym          = reinterpret_cast<SYMBOL_INFO*>(buf);
        sym->SizeOfStruct  = sizeof(SYMBOL_INFO);
        sym->MaxNameLen    = MAX_SYM_NAME;

        DWORD64 disp = 0;
        if (SymFromAddr(process, address, &disp, sym)) {
            outDisplacement = disp;
            return std::string(sym->Name, sym->NameLen);
        }
        outDisplacement = 0;
        return {};
    }

    static std::pair<std::string, std::uint32_t> ResolveSourceLine(HANDLE process, std::uint64_t address)
    {
        IMAGEHLP_LINE64 line{ .SizeOfStruct = sizeof(IMAGEHLP_LINE64) };
        DWORD           disp = 0;
        if (SymGetLineFromAddr64(process, address, &disp, &line))
            return { line.FileName, line.LineNumber };
        return {};
    }

    static std::pair<std::string, std::uint64_t> ResolveModule(HANDLE process, std::uint64_t address)
    {
        IMAGEHLP_MODULE64 mod{ .SizeOfStruct = sizeof(IMAGEHLP_MODULE64) };
        if (SymGetModuleInfo64(process, address, &mod))
            return { mod.ModuleName, mod.BaseOfImage };
        return {};
    }

    std::vector<StackFrame> Walk(CONTEXT* ctx, std::size_t maxFrames)
    {
        // Work on a copy so StackWalk64 doesn't clobber the original context.
        CONTEXT ctxCopy = *ctx;

        HANDLE process = GetCurrentProcess();
        HANDLE thread  = GetCurrentThread();

        std::lock_guard lock(s_dbghelpMutex);

        SymInitialize(process, nullptr, TRUE);
        SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS);

        STACKFRAME64 frame{};
        frame.AddrPC.Offset    = ctxCopy.Rip;
        frame.AddrPC.Mode      = AddrModeFlat;
        frame.AddrFrame.Offset = ctxCopy.Rbp;
        frame.AddrFrame.Mode   = AddrModeFlat;
        frame.AddrStack.Offset = ctxCopy.Rsp;
        frame.AddrStack.Mode   = AddrModeFlat;

        std::vector<StackFrame> result;
        result.reserve(64);

        for (std::size_t i = 0; i < maxFrames; ++i) {
            if (!StackWalk64(
                    IMAGE_FILE_MACHINE_AMD64,
                    process,
                    thread,
                    &frame,
                    &ctxCopy,
                    nullptr,
                    SymFunctionTableAccess64,
                    SymGetModuleBase64,
                    nullptr)) {
                break;
            }

            if (frame.AddrPC.Offset == 0)
                break;

            StackFrame sf;
            sf.address = frame.AddrPC.Offset;

            auto [modName, modBase]  = ResolveModule(process, sf.address);
            sf.moduleName            = std::move(modName);
            sf.moduleBase            = modBase;
            sf.symbolName            = ResolveSymbol(process, sf.address, sf.symbolDisplacement);
            auto [srcFile, srcLine]  = ResolveSourceLine(process, sf.address);
            sf.sourceFile            = std::move(srcFile);
            sf.sourceLine            = srcLine;

            result.push_back(std::move(sf));
        }

        SymCleanup(process);
        return result;
    }

    std::vector<ScannedValue> ScanStack(const CONTEXT* ctx, std::size_t maxBytes)
    {
        std::vector<ScannedValue> result;

        const std::uint64_t rsp = ctx->Rsp;
        if (rsp == 0)
            return result;

        __try {
            // Clamp the read window to the end of the committed stack region so
            // we never touch the guard page (which would itself fault).
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<void*>(rsp), &mbi, sizeof(mbi)) == 0)
                return result;

            const std::uint64_t regionEnd =
                reinterpret_cast<std::uint64_t>(mbi.BaseAddress) + mbi.RegionSize;

            std::uint64_t end = rsp + maxBytes;
            if (end > regionEnd)
                end = regionEnd;

            result.reserve(256);
            for (std::uint64_t addr = (rsp + 7) & ~std::uint64_t{ 7 }; addr + 8 <= end; addr += 8) {
                const auto value = *reinterpret_cast<const std::uint64_t*>(addr);

                // Keep only values that could be a canonical user-mode pointer.
                // Non-pointer scalars and small integers are filtered by the caller
                // when it fails to resolve them to a module or RTTI object.
                if (value >= 0x10000 && value <= 0x7FFFFFFEFFFF)
                    result.push_back({ addr, value });
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        return result;
    }
}
