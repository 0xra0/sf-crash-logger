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

    static BOOL CALLBACK EnumModulesCallback(PCSTR moduleName, DWORD64 moduleBase, ULONG moduleSize, PVOID userContext)
    {
        auto* modules = static_cast<std::vector<ModuleInfo>*>(userContext);

        char pathBuf[MAX_PATH] = {};
        HANDLE process = GetCurrentProcess();

        HMODULE hmod = reinterpret_cast<HMODULE>(moduleBase);
        GetModuleFileNameExA(process, hmod, pathBuf, MAX_PATH);

        ModuleInfo info;
        info.name = moduleName;
        info.path = pathBuf;
        info.base = moduleBase;
        info.size = moduleSize;
        info.version = GetFileVersion(pathBuf);

        // Check if it lives in the SFSE plugins directory
        try {
            auto pluginsDir  = GetSFSEPluginsDir();
            auto modulePath  = std::filesystem::path(pathBuf);
            info.isSFSEPlugin = modulePath.parent_path() == pluginsDir;
        } catch (...) {}

        modules->push_back(std::move(info));
        return TRUE;
    }

    std::vector<ModuleInfo> GetAll()
    {
        std::vector<ModuleInfo> modules;
        modules.reserve(128);

        EnumerateLoadedModulesA64(GetCurrentProcess(), EnumModulesCallback, &modules);

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
