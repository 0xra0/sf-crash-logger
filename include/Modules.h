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
    std::vector<ModuleInfo> GetAll();

    // Returns the module that contains the given address, or nullptr if none.
    // The returned pointer is valid for the lifetime of the passed-in vector.
    const ModuleInfo* FindModule(std::uint64_t address, const std::vector<ModuleInfo>& modules);

    // Returns the module name (without path) that contains the given address,
    // or an empty string if not found.
    std::string NameFromAddress(std::uint64_t address, const std::vector<ModuleInfo>& modules);
}
