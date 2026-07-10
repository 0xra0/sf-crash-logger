#include "PCH.h"
#include "CrashSignature.h"
#include "AddressLibrary.h"

#include <cctype>

namespace CrashSignature
{
    // The fault site plus three callers. Enough to separate distinct bugs that
    // share a leaf function; few enough that the same bug reached by slightly
    // different paths still hashes alike.
    static constexpr std::size_t kFrames = 4;

    // 64-bit FNV-1a: a few lines, no dependency, no allocation. The signature has
    // to be computable on the crash path, and it is an identifier, not a MAC.
    static constexpr std::uint64_t kFnvOffset = 1469598103934665603ull;
    static constexpr std::uint64_t kFnvPrime  = 1099511628211ull;

    static std::uint64_t Fnv1a(std::string_view s, std::uint64_t h)
    {
        for (const unsigned char c : s) {
            h ^= c;
            h *= kFnvPrime;
        }
        return h;
    }

    // Module names must fold case: the loader reports whatever the filesystem
    // gave it, and two users must not get different signatures for that.
    static std::string Lower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

    // `stable` is false only for an address inside the game executable that has no
    // Address Library ID. Such a token would be a raw offset, different on every
    // game version — the one thing this signature exists to avoid.
    struct Token
    {
        std::string text;
        bool        stable;
    };

    static Token TokenFor(std::uint64_t                  addr,
                          const std::vector<ModuleInfo>& modules,
                          std::uint64_t                  gameBase,
                          std::uint64_t                  gameEnd)
    {
        if (gameBase != 0 && addr >= gameBase && addr < gameEnd) {
            if (const auto id = AddressLibrary::Resolve(addr))
                return { std::format("id:{}", id->id), true };
            return { "game:?", false };
        }

        if (const auto* m = Modules::FindModule(addr, modules))
            return { std::format("{}+0x{:X}", Lower(m->name), addr - m->base), true };

        // In no loaded module at all. Uninformative, but it is the same everywhere,
        // so it neither helps nor harms comparability.
        return { "?", true };
    }

    // Win32-free core, so it can be exercised directly.
    static Result ComputeFrom(std::uint32_t                  code,
                              std::optional<std::uint32_t>   accessOp,
                              const std::vector<StackFrame>& frames,
                              const std::vector<ModuleInfo>& modules,
                              std::uint64_t                  gameBase,
                              std::uint64_t                  gameEnd)
    {
        Result r;
        if (frames.empty()) {
            r.reason = "no stack frames to hash";
            return r;
        }

        // Without the game module's bounds we cannot tell a game address from any
        // other, so a game frame would be hashed as a raw, version-specific offset
        // while looking perfectly stable. Refuse rather than mislead.
        if (gameBase == 0 || gameEnd <= gameBase) {
            r.reason = "could not locate the game module";
            return r;
        }

        std::vector<std::string> tokens;
        tokens.push_back(std::format("exc:{:08X}", code));
        if (accessOp)
            tokens.push_back(std::format("acc:{}",
                *accessOp == 1 ? 'w' : *accessOp == 8 ? 'x' : 'r'));

        const auto n = std::min(frames.size(), kFrames);
        for (std::size_t i = 0; i < n; ++i) {
            auto t = TokenFor(frames[i].address, modules, gameBase, gameEnd);
            if (!t.stable) {
                r.reason = "no Address Library database for this game version";
                return r;
            }
            tokens.push_back(std::move(t.text));
        }

        std::uint64_t h = kFnvOffset;
        for (const auto& t : tokens) {
            h = Fnv1a(t, h);
            h = Fnv1a("|", h);   // separator: "ab"+"c" must not collide with "a"+"bc"
        }

        r.available = true;
        // Fold the high half down so all 64 bits inform the printed 32.
        r.value  = std::format("{:08X}", static_cast<std::uint32_t>(h ^ (h >> 32)));
        r.inputs = std::move(tokens);
        return r;
    }

    static bool GameModuleBounds(std::uint64_t& base, std::uint64_t& end)
    {
        HMODULE h = GetModuleHandleW(nullptr);
        if (!h)
            return false;

        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi)))
            return false;

        base = reinterpret_cast<std::uint64_t>(mi.lpBaseOfDll);
        end  = base + mi.SizeOfImage;
        return end > base;
    }

    Result Compute(std::uint32_t                  exceptionCode,
                   std::optional<std::uint32_t>   accessOp,
                   const std::vector<StackFrame>& frames,
                   const std::vector<ModuleInfo>& modules)
    {
        try {
            std::uint64_t gameBase = 0, gameEnd = 0;
            GameModuleBounds(gameBase, gameEnd);   // zeroes on failure: handled below
            return ComputeFrom(exceptionCode, accessOp, frames, modules, gameBase, gameEnd);
        } catch (const std::exception&) {
            Result r;
            r.reason = "signature computation failed";
            return r;
        }
    }
}
