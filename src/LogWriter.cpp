#include "PCH.h"
#include "LogWriter.h"
#include "AddressLibrary.h"
#include "Breadcrumbs.h"
#include "CrashSignature.h"
#include "LoadOrder.h"
#include "SystemInfo.h"
#include "ThreadInfo.h"

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

    // Well-known debug-allocator fill patterns. A value that is one of these
    // (optionally plus a small field offset, from dereferencing a poison pointer)
    // pins the bug class instantly — no debugger needed.
    struct PoisonPattern
    {
        std::uint32_t word;
        const char*   meaning;
    };
    static constexpr PoisonPattern kPoison[] = {
        { 0xCDCDCDCD, "uninitialized heap memory (new/malloc'd, never written)" },
        { 0xCCCCCCCC, "uninitialized stack memory" },
        { 0xDDDDDDDD, "freed heap memory (use-after-free)" },
        { 0xFEEEFEEE, "freed heap memory (use-after-free)" },
        { 0xFDFDFDFD, "heap guard bytes (buffer over/underrun)" },
        { 0xABABABAB, "freed HeapAlloc guard bytes (use-after-free)" },
        { 0xBAADF00D, "uninitialized memory (LocalAlloc)" },
        { 0xDEADBEEF, "sentinel / poison value" },
    };

    // If `value` is a poison pattern (or a poison pointer plus a small field
    // offset), return "<pattern> +0xNN" describing it, else empty.
    static std::string PoisonName(std::uint64_t value)
    {
        for (const auto& p : kPoison) {
            const std::uint64_t base = (static_cast<std::uint64_t>(p.word) << 32) | p.word;
            if (value >= base && value - base <= 0x10000) {
                const auto off = value - base;
                return off == 0 ? std::format("0x{:08X} — {}", p.word, p.meaning)
                                : std::format("0x{:08X}+0x{:X} — {}", p.word, off, p.meaning);
            }
        }
        return {};
    }

    // Find the general-purpose register whose value the fault address is based on
    // (fault == reg + small offset). Returns the closest such register, or empty.
    struct RegHit { const char* name; std::uint64_t value; std::uint64_t offset; };
    static std::optional<RegHit> CorrelateFaultRegister(std::uint64_t faultAddr, const CONTEXT* ctx)
    {
        constexpr std::uint64_t kWindow = 0x10000;   // 64 KiB — covers large structs
        const std::pair<const char*, std::uint64_t> regs[] = {
            { "RAX", ctx->Rax }, { "RCX", ctx->Rcx }, { "RDX", ctx->Rdx }, { "RBX", ctx->Rbx },
            { "RBP", ctx->Rbp }, { "RSI", ctx->Rsi }, { "RDI", ctx->Rdi }, { "R8",  ctx->R8  },
            { "R9",  ctx->R9  }, { "R10", ctx->R10 }, { "R11", ctx->R11 }, { "R12", ctx->R12 },
            { "R13", ctx->R13 }, { "R14", ctx->R14 }, { "R15", ctx->R15 },
        };
        std::optional<RegHit> best;
        for (const auto& [name, value] : regs) {
            if (faultAddr < value || faultAddr - value > kWindow)
                continue;
            const auto off = faultAddr - value;
            if (!best || off < best->offset)
                best = RegHit{ name, value, off };
        }
        return best;
    }

    static std::string AccessViolationDetail(const EXCEPTION_RECORD* rec)
    {
        if (rec->NumberParameters < 2)
            return {};
        const char* op = rec->ExceptionInformation[0] == 0 ? "read" :
                         rec->ExceptionInformation[0] == 1 ? "write" : "execute";
        return std::format("  Detail:  {} at address 0x{:016X}\n", op, rec->ExceptionInformation[1]);
    }

    // Classify an access-violation fault address into human-readable hints so a
    // reader doesn't need a debugger to recognise the common failure shapes:
    // near-null / sentinel / poison, and which register the address is based on.
    static std::string FaultAnalysis(const EXCEPTION_RECORD* rec, const CONTEXT* ctx)
    {
        if ((rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
             rec->ExceptionCode != EXCEPTION_IN_PAGE_ERROR) ||
            rec->NumberParameters < 2)
            return {};

        const auto addr = rec->ExceptionInformation[1];
        std::string out;

        // What the fault address itself looks like.
        if (addr < 0x1000)
            out += std::format(
                "  Note:    near-null dereference — null pointer read at field offset +0x{:X}\n", addr);
        else if (addr == 0xFFFFFFFFFFFFFFFFull)
            out += "  Note:    0xFFFF...FFFF — invalid/sentinel pointer (freed or corrupted object)\n";
        else if (auto p = PoisonName(addr); !p.empty())
            out += std::format("  Note:    fault address is {}\n", p);

        // Which register the fault address is based on (base pointer + field), and
        // what that base register holds — often the smoking gun.
        if (auto hit = CorrelateFaultRegister(addr, ctx)) {
            std::string base;
            if (hit->value == 0)
                base = " — null";
            else if (auto p = PoisonName(hit->value); !p.empty())
                base = std::format(" — {}", p);

            if (hit->offset == 0)
                out += std::format("  Note:    access via {} (= 0x{:016X}{})\n",
                    hit->name, hit->value, base);
            else
                out += std::format("  Note:    access via {}+0x{:X} (field of {} = 0x{:016X}{})\n",
                    hit->name, hit->offset, hit->name, hit->value, base);
        }

        return out;
    }

    // ---- fault region ------------------------------------------------------
    // The fault address alone cannot distinguish a wild pointer into never-
    // allocated space, a write into a read-only image page, a touch of a reserved-
    // but-uncommitted page, and a stack overflow. Asking the memory manager can.
    // Kept out of FaultAnalysis so that stays pure.

    static const char* ProtectName(DWORD p)
    {
        switch (p & 0xFF) {   // strip PAGE_GUARD / PAGE_NOCACHE / PAGE_WRITECOMBINE
        case PAGE_NOACCESS:           return "PAGE_NOACCESS";
        case PAGE_READONLY:           return "PAGE_READONLY";
        case PAGE_READWRITE:          return "PAGE_READWRITE";
        case PAGE_WRITECOPY:          return "PAGE_WRITECOPY";
        case PAGE_EXECUTE:            return "PAGE_EXECUTE";
        case PAGE_EXECUTE_READ:       return "PAGE_EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE:  return "PAGE_EXECUTE_READWRITE";
        case PAGE_EXECUTE_WRITECOPY:  return "PAGE_EXECUTE_WRITECOPY";
        default:                      return "unknown protection";
        }
    }

    static bool ProtectAllowsWrite(DWORD p)
    {
        switch (p & 0xFF) {
        case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    static bool ProtectAllowsExecute(DWORD p)
    {
        switch (p & 0xFF) {
        case PAGE_EXECUTE: case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    // PAGE_EXECUTE alone grants execute but not read.
    static bool ProtectAllowsRead(DWORD p)
    {
        const DWORD base = p & 0xFF;
        return base != 0 && base != PAGE_NOACCESS && base != PAGE_EXECUTE;
    }

    // `op` is EXCEPTION_RECORD::ExceptionInformation[0]: 0 read, 1 write, 8 DEP.
    static std::string FaultRegionDetail(std::uint64_t addr, ULONG_PTR op, const CrashContext& crash)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
            return std::format("  Region:  0x{:016X} lies outside the process address space\n", addr);

        std::string out;
        const auto  base = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);

        if (mbi.State == MEM_FREE) {
            out += "  Region:  not mapped — MEM_FREE, never allocated (wild or stale pointer)\n";
        } else {
            const char* state = (mbi.State == MEM_COMMIT) ? "MEM_COMMIT" : "MEM_RESERVE";
            const char* type  = (mbi.Type == MEM_IMAGE)   ? "MEM_IMAGE"
                              : (mbi.Type == MEM_MAPPED)  ? "MEM_MAPPED"
                              : (mbi.Type == MEM_PRIVATE) ? "MEM_PRIVATE"
                                                          : "unknown type";
            out += std::format("  Region:  base 0x{:016X}, size 0x{:X}, {}, {}",
                base, static_cast<std::uint64_t>(mbi.RegionSize), state, type);
            if (mbi.State == MEM_COMMIT)
                out += std::format(", {}{}", ProtectName(mbi.Protect),
                    (mbi.Protect & PAGE_GUARD) ? " | PAGE_GUARD" : "");
            out += "\n";
        }

        // Why this particular access was refused, given what the page permits.
        if (mbi.State == MEM_COMMIT) {
            if (op == 1 && !ProtectAllowsWrite(mbi.Protect))
                out += "  Note:    write to non-writable memory\n";
            else if (op == 8 && !ProtectAllowsExecute(mbi.Protect))
                out += "  Note:    execute of non-executable memory (DEP)\n";
            else if (op == 0 && !ProtectAllowsRead(mbi.Protect))
                out += "  Note:    read from unreadable memory\n";

            if (mbi.Protect & PAGE_GUARD)
                out += "  Note:    guard page — first touch past the committed region\n";
        } else if (mbi.State == MEM_RESERVE) {
            out += "  Note:    address space is reserved but was never committed\n";
        }

        // Membership in the faulting thread's own stack is what turns an otherwise
        // anonymous reserved-page fault into a diagnosis of stack overflow. The
        // bounds come from the crash context: this may not be the crashing thread.
        if (crash.stackHigh > crash.stackLow && addr >= crash.stackLow && addr < crash.stackHigh) {
            out += std::format("  Note:    inside the crashing thread's stack (0x{:016X} - 0x{:016X})\n",
                crash.stackLow, crash.stackHigh);
            if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD))
                out += "  Note:    the stack has not grown this far — stack overflow\n";
        }

        return out;
    }

    static std::string FaultRegion(const EXCEPTION_RECORD* rec, const CrashContext& crash)
    {
        if ((rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
             rec->ExceptionCode != EXCEPTION_IN_PAGE_ERROR) ||
            rec->NumberParameters < 2)
            return {};
        return FaultRegionDetail(rec->ExceptionInformation[1], rec->ExceptionInformation[0], crash);
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

    // This plugin's own version, e.g. "0.2.0". The single source of truth is
    // set_version() in xmake.lua, which the build bakes into the exported
    // SFSEPlugin_Version block; read it back rather than keeping a second copy
    // here that a version bump would silently leave stale. REL::Version::string()
    // would render the unused build field too ("0.2.0.0"), so format it directly.
    static std::string PluginVersion()
    {
        if (const auto* pvd = SFSE::PluginVersionData::GetSingleton()) {
            const auto v = pvd->GetPluginVersion();
            return std::format("{}.{}.{}", v.major(), v.minor(), v.patch());
        }
        return "unknown";
    }

    // "  ID: <id>+0xoffset" if the address resolves to an Address Library ID
    // (only game-executable addresses do), else empty.
    static std::string IdSuffix(std::uint64_t addr)
    {
        if (auto r = AddressLibrary::Resolve(addr))
            return std::format("  ID: {}+0x{:X}", r->id, r->displacement);
        return {};
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
            s += IdSuffix(value);
            return s;
        }
        // Not inside any module image — might be a live object. Ask the RTTI reader.
        auto type = RTTIReader::GetTypeName(value);
        if (!type.empty())
            return std::format("<object: {}>", type);
        // Or a recognisable debug-allocator fill pattern (uninitialized/freed).
        if (auto p = PoisonName(value); !p.empty())
            return std::format("<poison: {}>", p);
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
        const CrashContext&              crash,
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

        const auto* rec = crash.ep->ExceptionRecord;
        const auto* ctx = crash.ep->ContextRecord;

        // ------------------------------------------------------------------ header
        // Access type feeds the signature: a read and a write at the same site are
        // different bugs. nullopt for exceptions that carry no access information.
        std::optional<std::uint32_t> accessOp;
        if ((rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
             rec->ExceptionCode == EXCEPTION_IN_PAGE_ERROR) &&
            rec->NumberParameters >= 2)
            accessOp = static_cast<std::uint32_t>(rec->ExceptionInformation[0]);

        const auto signature = CrashSignature::Compute(rec->ExceptionCode, accessOp, frames, modules);

        out << std::format("Starfield Crash Logger v{}\n", PluginVersion());
        out << std::format("Timestamp: {}\n", ReadableTimestamp());
        out << std::format("Address Library: {}\n", AddressLibrary::Status());
        out << std::format("Crash signature: {}\n\n",
            signature.available ? signature.value
                                : std::format("unavailable ({})", signature.reason));

        // ------------------------------------------------------------------ exception
        const auto  excAddr = reinterpret_cast<std::uint64_t>(rec->ExceptionAddress);
        const auto  excMod  = ModuleOffset(excAddr, modules);
        const auto* excModI = Modules::FindModule(excAddr, modules);

        out << "EXCEPTION\n";
        out << std::format("  Code:    0x{:08X} ({})\n", rec->ExceptionCode, ExceptionCodeName(rec->ExceptionCode));
        out << std::format("  Address: 0x{:016X}", excAddr);
        if (!excMod.empty())
            out << std::format(" ({}{})", excMod, (excModI && excModI->isSFSEPlugin) ? " [SFSE]" : "");
        out << IdSuffix(excAddr) << "\n";
        // The same fault means different things on the main thread and on a worker.
        out << std::format("  Thread:  {}\n", ThreadInfo::Describe(crash.threadId));

        if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
            rec->ExceptionCode == EXCEPTION_IN_PAGE_ERROR) {
            out << AccessViolationDetail(rec);
            out << FaultAnalysis(rec, ctx);
            out << FaultRegion(rec, crash);
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
            out << std::format("  Faulting module: {}{}\n",
                excMod.empty() ? "unknown" : excMod, IdSuffix(excAddr));

            // Show exactly what the signature hashed, so it can be reproduced and
            // argued with rather than taken on faith.
            if (signature.available && !signature.inputs.empty()) {
                std::string joined = signature.inputs.front();
                for (std::size_t i = 1; i < signature.inputs.size(); ++i)
                    joined += std::format(" | {}", signature.inputs[i]);
                out << std::format("  Signature {} over: {}\n", signature.value, joined);
            }
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

        // ------------------------------------------------------------------ system
        // The static facts were captured at plugin load; memory is sampled right
        // here, because a crash caused by commit exhaustion is only visible in the
        // numbers as they stood at the fault. Memory is therefore still reported
        // even when the static capture never ran.
        out << "SYSTEM\n";
        if (!SystemInfo::Available()) {
            out << "  (OS/CPU/GPU captured at plugin load — this crash preceded it)\n";
        } else {
            const auto& wine = SystemInfo::Wine();
            out << std::format("  OS:       {}\n", SystemInfo::OS());
            out << std::format("  Wine:     {}\n",
                wine.empty() ? "not detected (native Windows)" : wine.c_str());
            out << std::format("  CPU:      {}\n", SystemInfo::CPU());
            out << std::format("  GPU:      {}\n", SystemInfo::GPU());
        }
        out << std::format("  Memory:   {}\n", SystemInfo::SystemMemory());
        out << std::format("  Process:  {}\n", SystemInfo::ProcessMemory());
        out << "\n";

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
        out << std::format("STACK TRACE ({} frames, unwind-data walk)\n", frames.size());
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
            out << IdSuffix(f.address) << "\n";

            if (!f.sourceFile.empty())
                out << std::format("          {}:{}\n", f.sourceFile, f.sourceLine);
        }
        out << "\n";

        // ------------------------------------------------------------------ stack scan
        // Every value on the raw stack that resolves to a module (return address)
        // or a live RTTI object. Recovers the deeper frames the strict unwinder
        // above drops when a function is missing or has corrupt unwind data.
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
        out << "\n";

        // ------------------------------------------------------------------ plugins
        // Content load order (.esm/.esp/.esl) from Plugins.txt — the mods the
        // module list above can't show, since content plugins aren't DLLs.
        {
            const auto& lo = LoadOrder::Entries();
            if (!LoadOrder::Available()) {
                // Empty path means we never got as far as looking: either the
                // shell lookup failed, or we crashed before LoadOrder::Init().
                const auto where = LoadOrder::SourcePath();
                out << "PLUGINS (content load order)\n";
                if (where.empty())
                    out << "  (load order unavailable)\n\n";
                else
                    out << std::format("  (not found at {})\n\n", where);
            } else {
                std::size_t enabled = 0;
                for (const auto& e : lo)
                    enabled += e.enabled ? 1 : 0;
                out << std::format("PLUGINS (content load order — {} listed, {} enabled)\n",
                    lo.size(), enabled);

                // The index counts enabled plugins only — a disabled entry takes up
                // no load slot. It is a position in the load order, not a FormID mod
                // index: base-game masters are implicit and never appear in Plugins.txt.
                std::size_t slot = 0;
                for (const auto& e : lo) {
                    if (e.enabled)
                        out << std::format("  [{:>3}] {}\n", slot++, e.name);
                    else
                        out << std::format("  [   ] {}  (disabled)\n", e.name);
                }
                if (lo.empty())
                    out << "  (none listed)\n";
                out << "\n";
            }
        }

        out << "-- end of crash log --\n";
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

        out << std::format("[{}] CrashLogger v{} loaded — crash logs -> {}\n",
            ReadableTimestamp(), PluginVersion(), logDir.string());
        out.flush();
    }

    void WriteMiniDump(
        const CrashContext&          crash,
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

        // ThreadId must name the thread that crashed, not the one writing the dump:
        // it is what a debugger selects on open. ClientPointers stays FALSE because
        // ExceptionPointers is an address in this process either way.
        MINIDUMP_EXCEPTION_INFORMATION mei{
            .ThreadId          = crash.threadId,
            .ExceptionPointers = crash.ep,
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
