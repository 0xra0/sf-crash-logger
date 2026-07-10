#include "PCH.h"
#include "StackWalker.h"

namespace StackWalker
{
    // DbgHelp is not thread-safe; all calls must be serialized. Timed, not plain:
    // on the crash path a lock held by a thread that will never run again — or by
    // this thread, if a fault inside dbghelp re-enters us — would hang the report
    // forever. Frames matter more than symbols, so we give up waiting.
    static std::timed_mutex          s_dbghelpMutex;
    static constexpr auto            kSymbolLockWait = std::chrono::seconds(2);

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

    std::size_t Unwind(const CONTEXT* ctx, std::uint64_t* out, std::size_t maxFrames)
    {
        if (!ctx || !out || maxFrames == 0)
            return 0;

        CONTEXT     c = *ctx;   // unwinding mutates the context; keep the caller's
        std::size_t n = 0;

        __try {
            std::uint64_t lastRsp = 0;
            while (n < maxFrames && c.Rip != 0) {
                out[n++] = c.Rip;

                // The stack must move towards higher addresses on every frame.
                // Corrupt unwind data can otherwise spin us forever.
                if (c.Rsp <= lastRsp && lastRsp != 0)
                    break;
                lastRsp = c.Rsp;

                DWORD64 imageBase = 0;
                auto*   function  = RtlLookupFunctionEntry(c.Rip, &imageBase, nullptr);

                if (!function) {
                    // A leaf function with no unwind data: by the x64 ABI it cannot
                    // have moved RSP, so its return address is sitting at [RSP].
                    if (c.Rsp == 0)
                        break;
                    c.Rip = *reinterpret_cast<const std::uint64_t*>(c.Rsp);
                    c.Rsp += sizeof(std::uint64_t);
                    continue;
                }

                PVOID   handlerData      = nullptr;
                DWORD64 establisherFrame = 0;
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, c.Rip, function, &c,
                    &handlerData, &establisherFrame, nullptr);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // A bad frame ends the walk; everything captured so far still stands.
        }

        return n;
    }

    std::vector<StackFrame> Walk(CONTEXT* ctx, std::size_t maxFrames)
    {
        constexpr std::size_t kMaxAddresses = 256;
        if (maxFrames > kMaxAddresses)
            maxFrames = kMaxAddresses;

        // Frames first, with no dependency on dbghelp: whatever happens below, the
        // report gets a stack.
        std::uint64_t     addresses[kMaxAddresses]{};
        const std::size_t count = Unwind(ctx, addresses, maxFrames);

        std::vector<StackFrame> result;
        result.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            StackFrame sf;
            sf.address = addresses[i];
            result.push_back(std::move(sf));
        }

        std::unique_lock lock(s_dbghelpMutex, std::defer_lock);
        if (!lock.try_lock_for(kSymbolLockWait))
            return result;   // symbols are a nicety; addresses are the evidence

        HANDLE process = GetCurrentProcess();

        // Set options BEFORE SymInitialize: with fInvadeProcess = TRUE it enumerates
        // and registers every loaded module up front, and only SYMOPT_DEFERRED_LOADS
        // (which must already be set at that point) keeps it from eagerly loading
        // every PDB — an expensive, heap-heavy operation at the worst possible moment.
        SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS);
        if (!SymInitialize(process, nullptr, TRUE))
            return result;

        for (auto& sf : result) {
            auto [modName, modBase] = ResolveModule(process, sf.address);
            sf.moduleName           = std::move(modName);
            sf.moduleBase           = modBase;
            sf.symbolName           = ResolveSymbol(process, sf.address, sf.symbolDisplacement);
            auto [srcFile, srcLine] = ResolveSourceLine(process, sf.address);
            sf.sourceFile           = std::move(srcFile);
            sf.sourceLine           = srcLine;
        }

        SymCleanup(process);
        return result;
    }

    // A function containing __try may not also contain objects that require
    // unwinding: MSVC rejects it outright (C2712) and clang miscompiles it under
    // /EHa. So the guarded read fills a caller-provided buffer — no allocation, no
    // destructors — and the vector lives in ScanStack, outside the guard.
    static std::size_t ScanRaw(std::uint64_t rsp, std::size_t maxBytes,
        ScannedValue* out, std::size_t maxOut) noexcept
    {
        std::size_t n = 0;
        __try {
            // Clamp the read window to the end of the committed stack region so
            // we never touch the guard page (which would itself fault).
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<void*>(rsp), &mbi, sizeof(mbi)) == 0)
                return 0;

            const std::uint64_t regionEnd =
                reinterpret_cast<std::uint64_t>(mbi.BaseAddress) + mbi.RegionSize;

            std::uint64_t end = rsp + maxBytes;
            if (end > regionEnd)
                end = regionEnd;

            for (std::uint64_t addr = (rsp + 7) & ~std::uint64_t{ 7 };
                 addr + 8 <= end && n < maxOut; addr += 8) {
                const auto value = *reinterpret_cast<const std::uint64_t*>(addr);

                // Keep only values that could be a canonical user-mode pointer.
                // Non-pointer scalars and small integers are filtered by the caller
                // when it fails to resolve them to a module or RTTI object.
                if (value >= 0x10000 && value <= 0x7FFFFFFEFFFF) {
                    out[n].stackAddress = addr;
                    out[n].value        = value;
                    ++n;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        return n;
    }

    std::vector<ScannedValue> ScanStack(const CONTEXT* ctx, std::size_t maxBytes)
    {
        const std::uint64_t rsp = ctx->Rsp;
        if (rsp == 0)
            return {};

        std::vector<ScannedValue> result(maxBytes / sizeof(std::uint64_t));
        result.resize(ScanRaw(rsp, maxBytes, result.data(), result.size()));
        return result;
    }
}
