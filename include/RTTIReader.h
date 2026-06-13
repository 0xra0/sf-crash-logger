#pragma once

namespace RTTIReader
{
    struct RegisterObject
    {
        std::string   regName;
        std::uint64_t value{};
        std::string   typeName;  // demangled, e.g. "RE::Actor"
    };

    // Try to read the MSVC RTTI type name of the object at address ptr.
    // Returns empty string if ptr does not point to a valid RTTI object.
    std::string GetTypeName(std::uint64_t ptr);

    // For each general-purpose register in ctx, attempt RTTI identification.
    // Only registers whose values look like valid object pointers are included.
    std::vector<RegisterObject> IdentifyRegisters(const CONTEXT* ctx);
}
