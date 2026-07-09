#include "PCH.h"
#include "RTTIReader.h"

// Windows x64 MSVC RTTI layout (without needing /GR in our own build):
//
//   object[0]  = vtable ptr (V)
//   V[-1]      = RVA of RTTICompleteObjectLocator from its owning image base
//   COL.pTypeDescriptor = RVA of TypeDescriptor from same image base
//   TypeDescriptor.name = mangled class name, e.g. ".?AVActor@RE@@"

namespace RTTIReader
{
    // Windows x64 RTTI structures (MSVC ABI)
    struct RTTITypeDescriptor
    {
        void* pVFTable;
        void* spare;
        char  name[1];  // variable length, mangled: ".?AVClassName@Namespace@@"
    };

    struct RTTICompleteObjectLocator
    {
        std::uint32_t signature;               // 1 = x64
        std::uint32_t offset;
        std::uint32_t cdOffset;
        std::int32_t  pTypeDescriptor;         // RVA from image base
        std::int32_t  pClassHierarchyDescriptor;
        std::int32_t  pSelf;                   // RVA of this COL from image base (x64)
    };

    static std::string Demangle(const char* mangled)
    {
        // Input: ".?AVMyClass@MyNamespace@@"
        // Output: "MyNamespace::MyClass"
        std::string_view sv(mangled);

        // Must start with ".?A" (class/struct/union marker)
        if (sv.size() < 5 || sv[0] != '.' || sv[1] != '?' || sv[2] != 'A')
            return {};

        // sv[3] is the type kind: 'V'=class, 'U'=struct, 'T'=union, 'W'=enum
        // Skip ".?AV" / ".?AU" / ".?AT" / ".?AW"
        sv.remove_prefix(4);

        // Strip trailing "@@"
        if (sv.ends_with("@@"))
            sv.remove_suffix(2);

        // The remaining parts are split by '@' in reverse namespace order:
        // "MyClass@NS2@NS1" → NS1::NS2::MyClass
        std::vector<std::string_view> parts;
        while (!sv.empty()) {
            auto sep = sv.find('@');
            auto part = sv.substr(0, sep);
            if (!part.empty())
                parts.push_back(part);
            if (sep == std::string_view::npos)
                break;
            sv.remove_prefix(sep + 1);
        }

        // Reverse: innermost scope is first in MSVC mangling
        std::string result;
        for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
            if (!result.empty())
                result += "::";
            result += *it;
        }
        return result;
    }

    static bool IsValidReadableAddress(std::uint64_t addr)
    {
        // Quick sanity checks before attempting a read
        if (addr < 0x10000 || addr > 0x7FFFFFFEFFFF)
            return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)))
            return false;

        constexpr DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
        return (mbi.State == MEM_COMMIT) && (mbi.Protect & readable) &&
               !(mbi.Protect & PAGE_GUARD);
    }

    std::string GetTypeName(std::uint64_t ptr)
    {
        __try {
            if (!IsValidReadableAddress(ptr))
                return {};

            // Read vtable pointer
            auto vtablePtr = *reinterpret_cast<std::uint64_t*>(ptr);
            if (!IsValidReadableAddress(vtablePtr - 8))
                return {};

            // vtable[-1] is the RVA of the RTTICompleteObjectLocator
            auto colRva = *reinterpret_cast<std::int32_t*>(vtablePtr - 8);

            // Find which module the vtable belongs to
            HMODULE hModule = nullptr;
            if (!GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCSTR>(vtablePtr),
                    &hModule) || !hModule) {
                return {};
            }
            auto* imageBase = reinterpret_cast<std::uint8_t*>(hModule);

            // Resolve COL from its RVA
            auto* col = reinterpret_cast<RTTICompleteObjectLocator*>(imageBase + colRva);
            if (!IsValidReadableAddress(reinterpret_cast<std::uint64_t>(col)))
                return {};

            // Validate x64 signature and self-referential RVA (extra sanity check)
            if (col->signature != 1)
                return {};
            if (reinterpret_cast<std::uint64_t>(imageBase + col->pSelf) !=
                reinterpret_cast<std::uint64_t>(col))
                return {};

            // Resolve TypeDescriptor
            auto* typeDesc = reinterpret_cast<RTTITypeDescriptor*>(imageBase + col->pTypeDescriptor);
            if (!IsValidReadableAddress(reinterpret_cast<std::uint64_t>(typeDesc)))
                return {};

            return Demangle(typeDesc->name);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return {};
        }
    }
}
