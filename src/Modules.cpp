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
            } catch (...) {}

            modules.push_back(std::move(info));
        }

        // Sort: game exe first, then SFSE plugins, then the rest alphabetically
        std::sort(modules.begin(), modules.end(), [](const ModuleInfo& a, const ModuleInfo& b) {
            if (a.isSFSEPlugin != b.isSFSEPlugin)
                return a.isSFSEPlugin > b.isSFSEPlugin;
            return a.name < b.name;
        });

        return modules;
    }

    std::string NameFromAddress(std::uint64_t address, const std::vector<ModuleInfo>& modules)
    {
        for (const auto& m : modules) {
            if (address >= m.base && address < m.base + m.size)
                return m.name;
        }
        return {};
    }
}
