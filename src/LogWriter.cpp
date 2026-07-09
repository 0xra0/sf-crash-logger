#include "PCH.h"
#include "LogWriter.h"
#include "Breadcrumbs.h"

namespace LogWriter
{
    static std::string ExceptionCodeName(DWORD code)
    {
        switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:         return "ACCESS_VIOLATION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_BREAKPOINT:               return "BREAKPOINT";
        case EXCEPTION_DATATYPE_MISALIGNMENT:    return "DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DENORMAL_OPERAND:     return "FLT_DENORMAL_OPERAND";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_INEXACT_RESULT:       return "FLT_INEXACT_RESULT";
        case EXCEPTION_FLT_INVALID_OPERATION:    return "FLT_INVALID_OPERATION";
        case EXCEPTION_FLT_OVERFLOW:             return "FLT_OVERFLOW";
        case EXCEPTION_FLT_STACK_CHECK:          return "FLT_STACK_CHECK";
        case EXCEPTION_FLT_UNDERFLOW:            return "FLT_UNDERFLOW";
        case EXCEPTION_ILLEGAL_INSTRUCTION:      return "ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR:            return "IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW:             return "INT_OVERFLOW";
        case EXCEPTION_INVALID_DISPOSITION:      return "INVALID_DISPOSITION";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "NONCONTINUABLE_EXCEPTION";
        case EXCEPTION_PRIV_INSTRUCTION:         return "PRIV_INSTRUCTION";
        case EXCEPTION_SINGLE_STEP:              return "SINGLE_STEP";
        case EXCEPTION_STACK_OVERFLOW:           return "STACK_OVERFLOW";
        default:                                 return std::format("0x{:08X}", code);
        }
    }

    static std::string AccessViolationDetail(const EXCEPTION_RECORD* rec)
    {
        if (rec->NumberParameters < 2)
            return {};
        const char* op = rec->ExceptionInformation[0] == 0 ? "read" :
                         rec->ExceptionInformation[0] == 1 ? "write" : "execute";
        return std::format("  Detail:  {} at address 0x{:016X}\n", op, rec->ExceptionInformation[1]);
    }

    // Classify an access-violation fault address into a human-readable hint so a
    // reader doesn't need a debugger to recognise the common failure shapes.
    static std::string FaultAnalysis(const EXCEPTION_RECORD* rec)
    {
        if ((rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
             rec->ExceptionCode != EXCEPTION_IN_PAGE_ERROR) ||
            rec->NumberParameters < 2)
            return {};

        const auto addr = rec->ExceptionInformation[1];
        if (addr < 0x1000)
            return std::format(
                "  Note:    near-null dereference — likely a null pointer read at field offset +0x{:X}\n",
                addr);
        if (addr == 0xFFFFFFFFFFFFFFFFull)
            return "  Note:    read at 0xFFFF...FFFF — invalid/sentinel pointer (freed or corrupted object)\n";
        return {};
    }

    // Base address of this plugin's own module. Used to exclude ourselves from
    // the "culprit" list — the crash handler is always on the stack.
    static std::uint64_t SelfModuleBase()
    {
        HMODULE h = nullptr;
        if (GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(&SelfModuleBase), &h) &&
            h)
            return reinterpret_cast<std::uint64_t>(h);
        return 0;
    }

    // "module+0xoffset" for an address inside a loaded module, else empty.
    static std::string ModuleOffset(std::uint64_t addr, const std::vector<ModuleInfo>& modules)
    {
        const auto* m = Modules::FindModule(addr, modules);
        if (!m)
            return {};
        return std::format("{}+0x{:X}", m->name, addr - m->base);
    }

    // Resolve a pointer-sized value to something meaningful: a module+offset
    // (a return address / code pointer), or an RTTI-typed game object on the heap.
    // Returns empty for values that are neither (plain data / non-pointers).
    static std::string Annotate(std::uint64_t value, const std::vector<ModuleInfo>& modules)
    {
        if (const auto* m = Modules::FindModule(value, modules)) {
            auto s = std::format("{}+0x{:X}", m->name, value - m->base);
            if (m->isSFSEPlugin)
                s += "  [SFSE]";
            return s;
        }
        // Not inside any module image — might be a live object. Ask the RTTI reader.
        auto type = RTTIReader::GetTypeName(value);
        if (!type.empty())
            return std::format("<object: {}>", type);
        return {};
    }

    static std::string ReadableTimestamp()
    {
        auto now  = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        localtime_s(&tm, &time);
        return std::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    }

    std::string MakeFileTimestamp()
    {
        auto now  = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        localtime_s(&tm, &time);
        return std::format("{:04}{:02}{:02}_{:02}{:02}{:02}",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    }

    // Fallback log root when the Documents known-folder cannot be resolved:
    // next to the game executable. Never returns a path built from a null
    // pointer (which would be undefined behaviour).
    static std::filesystem::path FallbackLogRoot()
    {
        wchar_t exe[MAX_PATH]{};
        if (GetModuleFileNameW(nullptr, exe, MAX_PATH) > 0)
            return std::filesystem::path(exe).parent_path();
        return std::filesystem::current_path();
    }

    std::filesystem::path GetLogDir()
    {
        wchar_t* docsPath = nullptr;
        const HRESULT hr  = SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_DEFAULT, nullptr, &docsPath);

        std::filesystem::path dir;
        if (SUCCEEDED(hr) && docsPath)
            dir = std::filesystem::path(docsPath) / "My Games" / "Starfield";
        else
            dir = FallbackLogRoot();

        CoTaskMemFree(docsPath);   // documented to be safe on failure / null
        return dir / "SFSE" / "Crashlogs";
    }

    void Write(
        EXCEPTION_POINTERS*              ep,
        const std::vector<StackFrame>&   frames,
        const std::vector<ScannedValue>& scanned,
        const std::vector<ModuleInfo>&   modules,
        const std::string&               fileTimestamp)
    {
        const auto logDir = GetLogDir();
        std::filesystem::create_directories(logDir);

        const auto logPath = logDir / std::format("crash_{}.log", fileTimestamp);
        std::ofstream out(logPath, std::ios::out | std::ios::trunc);
        if (!out)
            return;

        const auto* rec = ep->ExceptionRecord;
        const auto* ctx = ep->ContextRecord;

        // ------------------------------------------------------------------ header
        out << "Starfield Crash Logger v0.2.0\n";
        out << std::format("Timestamp: {}\n\n", ReadableTimestamp());

        // ------------------------------------------------------------------ exception
        const auto  excAddr = reinterpret_cast<std::uint64_t>(rec->ExceptionAddress);
        const auto  excMod  = ModuleOffset(excAddr, modules);
        const auto* excModI = Modules::FindModule(excAddr, modules);

        out << "EXCEPTION\n";
        out << std::format("  Code:    0x{:08X} ({})\n", rec->ExceptionCode, ExceptionCodeName(rec->ExceptionCode));
        out << std::format("  Address: 0x{:016X}", excAddr);
        if (!excMod.empty())
            out << std::format(" ({}{})", excMod, (excModI && excModI->isSFSEPlugin) ? " [SFSE]" : "");
        out << "\n";

        if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
            rec->ExceptionCode == EXCEPTION_IN_PAGE_ERROR) {
            out << AccessViolationDetail(rec);
            out << FaultAnalysis(rec);
        }
        out << "\n";

        // ------------------------------------------------------------------ analysis
        // List SFSE plugins that appear anywhere on the stack (unwound frames plus
        // scanned return addresses) — the quickest "which mod was running" pointer.
        {
            const auto selfBase = SelfModuleBase();

            std::vector<std::string> pluginsOnStack;
            auto note = [&](std::uint64_t addr) {
                const auto* m = Modules::FindModule(addr, modules);
                if (m && m->isSFSEPlugin && m->base != selfBase &&
                    std::find(pluginsOnStack.begin(), pluginsOnStack.end(), m->name) == pluginsOnStack.end())
                    pluginsOnStack.push_back(m->name);
            };
            for (const auto& f : frames)
                note(f.address);
            for (const auto& s : scanned)
                note(s.value);

            out << "ANALYSIS\n";
            out << std::format("  Faulting module: {}\n", excMod.empty() ? "unknown" : excMod);
            if (pluginsOnStack.empty()) {
                out << "  No SFSE-plugin code on the stack — the crash is inside the game engine\n";
                out << "  (a mod may still be responsible via altered data/forms).\n";
            } else {
                out << "  SFSE plugins present on the stack (possible culprits):\n";
                for (const auto& p : pluginsOnStack)
                    out << std::format("    - {}\n", p);
            }
            out << "\n";
        }

        // ------------------------------------------------------------------ breadcrumbs
        // The most recent early-warning trace lines (first-chance exceptions and
        // lifecycle markers) leading up to this crash. The full history — including
        // any prior silent-death session that produced no dump — is in the
        // continuously-flushed CrashLogger_trace.log alongside this file.
        {
            const auto recent = Breadcrumbs::Recent();
            if (!recent.empty()) {
                out << "RECENT BREADCRUMBS (newest last; full trail in CrashLogger_trace.log)\n";
                for (const auto& line : recent)
                    out << "  " << line << "\n";
                out << "\n";
            }
        }

        // ------------------------------------------------------------------ registers
        out << "REGISTERS\n";
        out << std::format("  RAX: {:016X}  RCX: {:016X}  RDX: {:016X}  RBX: {:016X}\n",
            ctx->Rax, ctx->Rcx, ctx->Rdx, ctx->Rbx);
        out << std::format("  RSP: {:016X}  RBP: {:016X}  RSI: {:016X}  RDI: {:016X}\n",
            ctx->Rsp, ctx->Rbp, ctx->Rsi, ctx->Rdi);
        out << std::format("   R8: {:016X}   R9: {:016X}  R10: {:016X}  R11: {:016X}\n",
            ctx->R8, ctx->R9, ctx->R10, ctx->R11);
        out << std::format("  R12: {:016X}  R13: {:016X}  R14: {:016X}  R15: {:016X}\n",
            ctx->R12, ctx->R13, ctx->R14, ctx->R15);
        out << std::format("  RIP: {:016X}  EFL: {:08X}\n", ctx->Rip, ctx->EFlags);
        out << "\n";

        // ------------------------------------------------------------------ register targets
        // Annotate each register with what it points at: module+offset for code
        // (function/vtable/return address), or an RTTI type for live game objects.
        {
            const std::pair<const char*, std::uint64_t> regs[] = {
                { "RAX", ctx->Rax }, { "RCX", ctx->Rcx }, { "RDX", ctx->Rdx }, { "RBX", ctx->Rbx },
                { "RBP", ctx->Rbp }, { "RSI", ctx->Rsi }, { "RDI", ctx->Rdi }, { "R8",  ctx->R8  },
                { "R9",  ctx->R9  }, { "R10", ctx->R10 }, { "R11", ctx->R11 }, { "R12", ctx->R12 },
                { "R13", ctx->R13 }, { "R14", ctx->R14 }, { "R15", ctx->R15 }, { "RIP", ctx->Rip },
            };
            std::string body;
            for (const auto& [name, value] : regs) {
                auto ann = Annotate(value, modules);
                if (!ann.empty())
                    body += std::format("  {:>3}: 0x{:016X}  -> {}\n", name, value, ann);
            }
            if (!body.empty()) {
                out << "REGISTER TARGETS (registers pointing at code or game objects)\n";
                out << body << "\n";
            }
        }

        // ------------------------------------------------------------------ stack trace
        out << std::format("STACK TRACE ({} frames, frame-pointer unwind)\n", frames.size());
        for (std::size_t i = 0; i < frames.size(); ++i) {
            const auto& f = frames[i];

            std::string moduleCtx;
            if (!f.moduleName.empty()) {
                moduleCtx = f.moduleBase != 0
                    ? std::format("{}+0x{:X}", f.moduleName, f.address - f.moduleBase)
                    : f.moduleName;
            }

            if (!f.symbolName.empty()) {
                out << std::format("  [{:>3}] 0x{:016X}  {}+0x{:X}",
                    i, f.address, f.symbolName, f.symbolDisplacement);
                if (!moduleCtx.empty())
                    out << std::format("  [{}]", moduleCtx);
            } else {
                out << std::format("  [{:>3}] 0x{:016X}", i, f.address);
                if (!moduleCtx.empty())
                    out << std::format("  [{}]", moduleCtx);
            }
            out << "\n";

            if (!f.sourceFile.empty())
                out << std::format("          {}:{}\n", f.sourceFile, f.sourceLine);
        }
        out << "\n";

        // ------------------------------------------------------------------ stack scan
        // Every value on the raw stack that resolves to a module (return address)
        // or a live RTTI object. Recovers the deeper frames the strict unwinder
        // above drops when optimised code omits frame-pointer/unwind data.
        out << "STACK SCAN (resolvable pointers on the stack; RSP-relative offsets)\n";
        {
            std::size_t   shown     = 0;
            std::uint64_t lastValue = 0;
            for (const auto& s : scanned) {
                if (s.value == lastValue)   // collapse runs of the same pointer
                    continue;
                auto ann = Annotate(s.value, modules);
                if (ann.empty())
                    continue;               // skip plain data / non-pointers
                lastValue = s.value;
                out << std::format("  [RSP+0x{:04X}] 0x{:016X}  {}\n",
                    s.stackAddress - ctx->Rsp, s.value, ann);
                if (++shown >= 200)         // bound very deep stacks
                    break;
            }
            if (shown == 0)
                out << "  (no resolvable pointers found)\n";
        }
        out << "\n";

        // ------------------------------------------------------------------ modules
        // `modules` arrives base-sorted (for FindModule); present it the readable
        // way instead — SFSE plugins first, then everything else alphabetically.
        out << std::format("MODULES ({} loaded)\n", modules.size());
        auto displayModules = modules;
        std::sort(displayModules.begin(), displayModules.end(),
            [](const ModuleInfo& a, const ModuleInfo& b) {
                if (a.isSFSEPlugin != b.isSFSEPlugin)
                    return a.isSFSEPlugin > b.isSFSEPlugin;
                return a.name < b.name;
            });
        for (const auto& m : displayModules) {
            out << std::format("  {:40s}  base: 0x{:016X}  size: 0x{:08X}",
                m.name, m.base, m.size);
            if (!m.version.empty())
                out << std::format("  ver: {}", m.version);
            if (m.isSFSEPlugin)
                out << "  [SFSE]";
            out << "\n";
        }

        out << "\n-- end of crash log --\n";
        out.flush();

        REX::INFO("Crash log: {}", logPath.string());
    }

    void WriteStartupLog()
    {
        const auto logDir = GetLogDir();
        std::filesystem::create_directories(logDir);

        const auto logPath = logDir / "CrashLogger.log";
        std::ofstream out(logPath, std::ios::out | std::ios::app);
        if (!out)
            return;

        out << std::format("[{}] CrashLogger v0.2.0 loaded — crash logs -> {}\n",
            ReadableTimestamp(), logDir.string());
        out.flush();
    }

    void WriteMiniDump(
        EXCEPTION_POINTERS*          ep,
        const std::filesystem::path& logDir,
        const std::string&           fileTimestamp)
    {
        const auto dmpPath = logDir / std::format("crash_{}.dmp", fileTimestamp);

        HANDLE hFile = CreateFileW(
            dmpPath.wstring().c_str(),
            GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hFile == INVALID_HANDLE_VALUE) {
            REX::ERROR("CrashLogger: could not create minidump file.");
            return;
        }

        MINIDUMP_EXCEPTION_INFORMATION mei{
            .ThreadId          = GetCurrentThreadId(),
            .ExceptionPointers = ep,
            .ClientPointers    = FALSE,
        };

        // Moderate dump size: global data, handles, unloaded modules, and memory
        // referenced from stack/registers. Avoids dumping the entire heap.
        const auto dumpType = static_cast<MINIDUMP_TYPE>(
            MiniDumpWithDataSegs              |
            MiniDumpWithHandleData            |
            MiniDumpWithUnloadedModules       |
            MiniDumpWithIndirectlyReferencedMemory);

        const BOOL ok = MiniDumpWriteDump(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            hFile,
            dumpType,
            &mei,
            nullptr,
            nullptr);

        CloseHandle(hFile);

        if (ok)
            REX::INFO("Minidump: {}", dmpPath.string());
        else
            REX::ERROR("CrashLogger: MiniDumpWriteDump failed (0x{:08X}).", GetLastError());
    }
}
