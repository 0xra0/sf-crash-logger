#pragma once

struct ModuleInfo
{
    std::string   name;
    std::string   path;
    std::uint64_t base{};
    std::uint32_t size{};
    std::string   version;
    bool          isSFSEPlugin{ false };
};

namespace Modules
{
    // Returns all loaded modules, sorted by base address (required by FindModule).
    std::vector<ModuleInfo> GetAll();

    // Returns the module that contains the given address, or nullptr if none.
    // Requires `modules` to be base-sorted, as returned by GetAll(); binary search.
    // The returned pointer is valid for the lifetime of the passed-in vector.
    const ModuleInfo* FindModule(std::uint64_t address, const std::vector<ModuleInfo>& modules);
}
