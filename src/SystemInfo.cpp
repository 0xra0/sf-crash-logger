#include "PCH.h"
#include "SystemInfo.h"

#include <cstring>
#include <intrin.h>

namespace SystemInfo
{
    static bool        s_ready = false;
    static std::string s_os;
    static std::string s_cpu;
    static std::string s_gpu;
    static std::string s_wine;

    // ---------------------------------------------------------------- helpers

    static std::string Narrow(const wchar_t* w)
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

    // GiB once a value is big enough to warrant it, MiB below that. A crash early
    // in startup has a working set of tens of MiB, and "0.0 GiB" says nothing.
    static std::string FormatBytes(std::uint64_t bytes)
    {
        constexpr double mib = 1024.0 * 1024.0;
        constexpr double gib = mib * 1024.0;
        if (static_cast<double>(bytes) >= gib)
            return std::format("{:.1f} GiB", static_cast<double>(bytes) / gib);
        return std::format("{:.1f} MiB", static_cast<double>(bytes) / mib);
    }

    static unsigned Percent(std::uint64_t used, std::uint64_t total)
    {
        if (total == 0)
            return 0;
        return static_cast<unsigned>((used * 100 + total / 2) / total);
    }

    // ---------------------------------------------------------------- detection

    // GetVersionEx reports a compatibility-shimmed version unless the binary
    // carries a matching manifest; RtlGetVersion always reports the real one.
    static void DetectOS()
    {
        s_os = "unknown";

        auto* nt = GetModuleHandleW(L"ntdll.dll");
        if (!nt)
            return;

        using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
        auto fn = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(nt, "RtlGetVersion"));
        if (!fn)
            return;

        OSVERSIONINFOW vi{};
        vi.dwOSVersionInfoSize = sizeof(vi);
        if (fn(&vi) == 0) {
            s_os = std::format("Windows {}.{}.{}",
                vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
        }
    }

    // Wine exports wine_get_version from ntdll; native Windows does not. That
    // single symbol is the whole test. Proton additionally runs us under Steam's
    // compatibility tooling, which it announces through the environment.
    static void DetectWine()
    {
        auto* nt = GetModuleHandleW(L"ntdll.dll");
        if (!nt)
            return;

        using WineGetVersionFn     = const char*(*)();
        using WineGetHostVersionFn = void (*)(const char**, const char**);

        auto getVersion = reinterpret_cast<WineGetVersionFn>(GetProcAddress(nt, "wine_get_version"));
        if (!getVersion)
            return;   // native Windows

        const char* ver = getVersion();
        s_wine = std::format("{}", ver ? ver : "unknown version");

        auto getHost = reinterpret_cast<WineGetHostVersionFn>(GetProcAddress(nt, "wine_get_host_version"));
        if (getHost) {
            const char* sysname = nullptr;
            const char* release = nullptr;
            getHost(&sysname, &release);
            if (sysname && release)
                s_wine += std::format(" (host: {} {})", sysname, release);
        }

        if (GetEnvironmentVariableA("STEAM_COMPAT_DATA_PATH", nullptr, 0) != 0)
            s_wine += " — Steam Proton";
    }

    static void DetectCPU()
    {
        std::string brand;

        int regs[4]{};
        __cpuid(regs, 0x80000000);
        if (static_cast<unsigned>(regs[0]) >= 0x80000004u) {
            char buf[49]{};   // 3 leaves x 16 bytes, NUL-terminated by zero-init
            for (int i = 0; i < 3; ++i) {
                __cpuid(regs, 0x80000002 + i);
                std::memcpy(buf + i * 16, regs, 16);
            }
            brand = buf;

            // Intel pads the brand string with leading spaces.
            const auto first = brand.find_first_not_of(' ');
            const auto last  = brand.find_last_not_of(' ');
            brand = (first == std::string::npos) ? std::string{} : brand.substr(first, last - first + 1);
        }

        SYSTEM_INFO si{};
        GetNativeSystemInfo(&si);

        s_cpu = brand.empty()
            ? std::format("unknown ({} logical cores)", si.dwNumberOfProcessors)
            : std::format("{} ({} logical cores)", brand, si.dwNumberOfProcessors);
    }

    static void DetectGPU()
    {
        std::vector<std::string> adapters;

        for (DWORD i = 0;; ++i) {
            DISPLAY_DEVICEW dd{};
            dd.cb = sizeof(dd);
            if (!EnumDisplayDevicesW(nullptr, i, &dd, 0))
                break;
            if (!(dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP))
                continue;   // inactive/mirroring adapters say nothing about the crash

            auto name = Narrow(dd.DeviceString);
            if (name.empty())
                continue;
            if (std::find(adapters.begin(), adapters.end(), name) == adapters.end())
                adapters.push_back(std::move(name));   // one entry per adapter, not per monitor
        }

        if (adapters.empty()) {
            s_gpu = "unknown";
            return;
        }
        s_gpu = adapters.front();
        for (std::size_t i = 1; i < adapters.size(); ++i)
            s_gpu += std::format(", {}", adapters[i]);
    }

    // ---------------------------------------------------------------- interface

    void Init()
    {
        if (s_ready)
            return;
        try {
            DetectOS();
            DetectWine();
            DetectCPU();
            DetectGPU();
            s_ready = true;
            REX::INFO("SystemInfo: {} | {} | {}{}", s_os, s_cpu, s_gpu,
                s_wine.empty() ? "" : std::format(" | Wine {}", s_wine));
        } catch (...) {
            s_ready = false;
        }
    }

    bool Available()
    {
        return s_ready;
    }

    const std::string& OS()
    {
        return s_os;
    }

    const std::string& CPU()
    {
        return s_cpu;
    }

    const std::string& GPU()
    {
        return s_gpu;
    }

    const std::string& Wine()
    {
        return s_wine;
    }

    std::string SystemMemory()
    {
        MEMORYSTATUSEX ms{};
        ms.dwLength = sizeof(ms);
        if (!GlobalMemoryStatusEx(&ms))
            return "unavailable";

        // ullTotalPageFile is the system commit limit, not a page-file size.
        // Commit exhaustion, not physical RAM, is what kills a heavily modded game.
        const std::uint64_t physUsed   = ms.ullTotalPhys - ms.ullAvailPhys;
        const std::uint64_t commitUsed = ms.ullTotalPageFile - ms.ullAvailPageFile;

        return std::format("physical {} / {} ({}% used), commit {} / {} ({}% used)",
            FormatBytes(physUsed), FormatBytes(ms.ullTotalPhys), Percent(physUsed, ms.ullTotalPhys),
            FormatBytes(commitUsed), FormatBytes(ms.ullTotalPageFile), Percent(commitUsed, ms.ullTotalPageFile));
    }

    std::string ProcessMemory()
    {
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);
        if (!GetProcessMemoryInfo(GetCurrentProcess(),
                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc)))
            return "unavailable";

        // Wine reports success but leaves the _EX-only PrivateUsage at zero, while
        // still filling PagefileUsage — which is the same private-commit figure.
        // Prefer PrivateUsage, fall back to PagefileUsage, so Proton users get a
        // real number instead of "0.0 MiB".
        const std::uint64_t privateCommit = pmc.PrivateUsage ? pmc.PrivateUsage : pmc.PagefileUsage;

        if (privateCommit == 0)
            return std::format("working set {} (private commit unavailable)",
                FormatBytes(pmc.WorkingSetSize));

        return std::format("private {}, working set {}",
            FormatBytes(privateCommit), FormatBytes(pmc.WorkingSetSize));
    }
}
