#include "PCH.h"
#include "LogWriter.h"

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

    std::filesystem::path GetLogDir()
    {
        wchar_t* docsPath = nullptr;
        SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_DEFAULT, nullptr, &docsPath);
        std::filesystem::path dir(docsPath);
        CoTaskMemFree(docsPath);
        return dir / "My Games" / "Starfield" / "SFSE" / "Crashlogs";
    }

    void Write(
        EXCEPTION_POINTERS*                            ep,
        const std::vector<StackFrame>&                 frames,
        const std::vector<ModuleInfo>&                 modules,
        const std::vector<RTTIReader::RegisterObject>& rttiObjects,
        const std::string&                             fileTimestamp)
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
        out << "Starfield Crash Logger v0.1.0\n";
        out << std::format("Timestamp: {}\n\n", ReadableTimestamp());

        // ------------------------------------------------------------------ exception
        out << "EXCEPTION\n";
        out << std::format("  Code:    0x{:08X} ({})\n", rec->ExceptionCode, ExceptionCodeName(rec->ExceptionCode));
        out << std::format("  Address: 0x{:016X}", reinterpret_cast<std::uint64_t>(rec->ExceptionAddress));

        const auto crashMod = Modules::NameFromAddress(
            reinterpret_cast<std::uint64_t>(rec->ExceptionAddress), modules);
        if (!crashMod.empty())
            out << std::format(" ({})", crashMod);
        out << "\n";

        if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
            rec->ExceptionCode == EXCEPTION_IN_PAGE_ERROR) {
            out << AccessViolationDetail(rec);
        }
        out << "\n";

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

        // ------------------------------------------------------------------ RTTI objects
        if (!rttiObjects.empty()) {
            out << "PROBABLE GAME OBJECTS (from registers)\n";
            for (const auto& obj : rttiObjects)
                out << std::format("  {:3s}: 0x{:016X}  -> {}\n",
                    obj.regName, obj.value, obj.typeName);
            out << "\n";
        }

        // ------------------------------------------------------------------ stack trace
        out << std::format("STACK TRACE ({} frames)\n", frames.size());
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

        // ------------------------------------------------------------------ modules
        out << std::format("MODULES ({} loaded)\n", modules.size());
        for (const auto& m : modules) {
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

        out << std::format("[{}] CrashLogger v0.1.0 loaded — crash logs -> {}\n",
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
