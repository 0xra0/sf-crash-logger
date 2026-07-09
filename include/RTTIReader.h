#pragma once

namespace RTTIReader
{
    // Try to read the MSVC RTTI type name of the object at address ptr.
    // Returns empty string if ptr does not point to a valid RTTI object.
    std::string GetTypeName(std::uint64_t ptr);
}
