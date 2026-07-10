#include "PCH.h"
#include "Modules.h"

namespace Modules
{
    static std::string GetFileVersion(const std::string& path)
    {
        DWORD  dummy = 0;
        DWORD  size  = GetFileVersionInfoSizeA(path.c_str(), &dummy);
        if (size == 0)
            return {};

        std::vector<std::byte> buf(size);
        if (!GetFileVersionInfoA(path.c_str(), 0, size, buf.data()))
            return {};

        VS_FIXEDFILEINFO* ffi = nullptr;
        UINT              len = 0;
        if (!VerQueryValueA(buf.data(), "\\", reinterpret_cast<void**>(&ffi), &len) || !ffi)
            return {};

        return std::format("{}.{}.{}.{}",
            HIWORD(ffi->dwFileVersionMS),
            LOWORD(ffi->dwFileVersionMS),
            HIWORD(ffi->dwFileVersionLS),
            LOWORD(ffi->dwFileVersionLS));
    }

    static std::filesystem::path GetSFSEPluginsDir()
    {
        char path[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        return std::filesystem::path(path).parent_path() / "Data" / "SFSE" / "Plugins";
    }

    std::vector<ModuleInfo> GetAll()
    {
        std::vector<ModuleInfo> modules;
        modules.reserve(128);

        HANDLE  process = GetCurrentProcess();
        HMODULE hMods[1024]{};
        DWORD   cbNeeded = 0;

        if (!EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded))
            return modules;

        const DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; ++i) {
            char       nameBuf[MAX_PATH]{};
            char       pathBuf[MAX_PATH]{};
            MODULEINFO modInfo{};

            if (!GetModuleInformation(process, hMods[i], &modInfo, sizeof(modInfo)))
                continue;

            GetModuleBaseNameA(process, hMods[i], nameBuf, MAX_PATH);
            GetModuleFileNameExA(process, hMods[i], pathBuf, MAX_PATH);

            ModuleInfo info;
            info.name    = nameBuf;
            info.path    = pathBuf;
            info.base    = reinterpret_cast<std::uint64_t>(modInfo.lpBaseOfDll);
            info.size    = modInfo.SizeOfImage;
            info.version = GetFileVersion(pathBuf);

            try {
                auto pluginsDir   = GetSFSEPluginsDir();
                info.isSFSEPlugin = (std::filesystem::path(pathBuf).parent_path() == pluginsDir);
            } catch (const std::exception&) {}

            modules.push_back(std::move(info));
        }

        // Sort by base address so FindModule can binary-search. Module images
        // never overlap, so base order is a total order over [base, base+size).
        // Presentation order (SFSE plugins first, then alphabetical) is applied by
        // the log writer on a copy when it prints the module list.
        std::sort(modules.begin(), modules.end(), [](const ModuleInfo& a, const ModuleInfo& b) {
            return a.base < b.base;
        });

        return modules;
    }

    // Binary search over base-sorted modules (see GetAll). Called once per
    // scanned stack value and per register target, so O(log n) matters on the
    // deep stacks the scanner produces.
    const ModuleInfo* FindModule(std::uint64_t address, const std::vector<ModuleInfo>& modules)
    {
        // First module whose base is strictly greater than address; the candidate
        // containing address, if any, is the one immediately before it.
        auto it = std::upper_bound(modules.begin(), modules.end(), address,
            [](std::uint64_t addr, const ModuleInfo& m) { return addr < m.base; });
        if (it == modules.begin())
            return nullptr;
        --it;
        if (address >= it->base && address < it->base + it->size)
            return &*it;
        return nullptr;
    }
}
