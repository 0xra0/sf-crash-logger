#include "PCH.h"
#include "AddressLibrary.h"

#include <fstream>

namespace AddressLibrary
{
    // One (offset, id) pair, kept sorted by offset for nearest-below lookup.
    struct Entry
    {
        std::uint32_t offset;
        std::uint32_t id;
    };

    using Version = std::array<std::uint16_t, 4>;

    static bool               s_available = false;
    static std::uint64_t      s_gameBase  = 0;
    static std::uint64_t      s_gameSize  = 0;
    static std::vector<Entry> s_entries;      // sorted by offset ascending
    static std::string        s_dbVersion;    // version of the DB we loaded
    static std::string        s_gameVersion;  // running game version

    // Attribute an address to an ID only while it plausibly lies within that ID's
    // function/object; past this it is almost certainly an unrelated later region.
    static constexpr std::uint64_t kMaxDisplacement = 0x100000;   // 1 MiB
    // Guard against a corrupt header driving a huge allocation.
    static constexpr std::uint32_t kMaxCount        = 8'000'000;

    static std::string VersionText(const Version& v)
    {
        return std::format("{}.{}.{}.{}", v[0], v[1], v[2], v[3]);
    }

    // ------------------------------------------------------------------------
    // Running game version, taken from the executable's ProductVersion string —
    // the same value the Address Library is keyed to (see CommonLib's IDDB).
    // Falls back to the fixed-info version if the string resource is absent.
    // ------------------------------------------------------------------------
    static bool GetGameVersion(Version& out)
    {
        wchar_t exe[MAX_PATH]{};
        if (GetModuleFileNameW(nullptr, exe, MAX_PATH) == 0)
            return false;

        DWORD dummy = 0;
        const DWORD size = GetFileVersionInfoSizeW(exe, &dummy);
        if (size == 0)
            return false;

        std::vector<std::byte> buf(size);
        if (!GetFileVersionInfoW(exe, 0, size, buf.data()))
            return false;

        out = { 0, 0, 0, 0 };

        void* val = nullptr;
        UINT  len = 0;
        if (VerQueryValueW(buf.data(), L"\\StringFileInfo\\040904B0\\ProductVersion", &val, &len) &&
            val && len) {
            std::wstring          s(static_cast<const wchar_t*>(val), len);
            std::wistringstream   ss(s);
            std::wstring          tok;
            for (std::size_t i = 0; i < 4 && std::getline(ss, tok, L'.'); ++i) {
                try {
                    out[i] = static_cast<std::uint16_t>(std::stoi(tok));
                } catch (...) {
                    out[i] = 0;
                }
            }
            return true;
        }

        VS_FIXEDFILEINFO* ffi = nullptr;
        UINT              flen = 0;
        if (VerQueryValueW(buf.data(), L"\\", reinterpret_cast<void**>(&ffi), &flen) && ffi) {
            out = { HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS),
                    HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS) };
            return true;
        }
        return false;
    }

    static void CaptureGameModule()
    {
        HMODULE h = GetModuleHandleW(nullptr);
        MODULEINFO mi{};
        if (h && GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) {
            s_gameBase = reinterpret_cast<std::uint64_t>(mi.lpBaseOfDll);
            s_gameSize = mi.SizeOfImage;
        }
    }

    template <class T>
    static bool Read(std::ifstream& in, T& v)
    {
        return static_cast<bool>(in.read(reinterpret_cast<char*>(&v), sizeof(T)));
    }

    // ------------------------------------------------------------------------
    // v1/v2: a delta/type-encoded stream of (id, offset) pairs. Decoder mirrors
    // CommonLib's REL::IDDB::unpack_file exactly (the format is defined by the
    // tool that writes these files, so any deviation yields wrong IDs).
    // ------------------------------------------------------------------------
    static bool LoadV2(std::ifstream& in, std::uint64_t ptrSize, std::uint32_t count)
    {
        if (count == 0 || count > kMaxCount || ptrSize == 0)
            return false;

        s_entries.clear();
        s_entries.reserve(count);

        std::uint8_t  type       = 0;
        std::uint64_t id         = 0;
        std::uint64_t offset     = 0;
        std::uint64_t prevID     = 0;
        std::uint64_t prevOffset = 0;

        for (std::uint32_t i = 0; i < count; ++i) {
            if (!Read(in, type))
                return false;
            const auto lo = static_cast<std::uint8_t>(type & 0x0F);
            const auto hi = static_cast<std::uint8_t>(type >> 4);

            std::uint8_t  b = 0;
            std::uint16_t w = 0;
            std::uint32_t d = 0;
            switch (lo) {
            case 0: if (!Read(in, id)) return false; break;
            case 1: id = prevID + 1; break;
            case 2: if (!Read(in, b)) return false; id = prevID + b; break;
            case 3: if (!Read(in, b)) return false; id = prevID - b; break;
            case 4: if (!Read(in, w)) return false; id = prevID + w; break;
            case 5: if (!Read(in, w)) return false; id = prevID - w; break;
            case 6: if (!Read(in, w)) return false; id = w; break;
            case 7: if (!Read(in, d)) return false; id = d; break;
            default: return false;
            }

            const std::uint64_t tmp = (hi & 8) ? (prevOffset / ptrSize) : prevOffset;
            b = 0; w = 0; d = 0;
            switch (hi & 7) {
            case 0: if (!Read(in, offset)) return false; break;
            case 1: offset = tmp + 1; break;
            case 2: if (!Read(in, b)) return false; offset = tmp + b; break;
            case 3: if (!Read(in, b)) return false; offset = tmp - b; break;
            case 4: if (!Read(in, w)) return false; offset = tmp + w; break;
            case 5: if (!Read(in, w)) return false; offset = tmp - w; break;
            case 6: if (!Read(in, w)) return false; offset = w; break;
            case 7: if (!Read(in, d)) return false; offset = d; break;
            default: return false;
            }
            if (hi & 8)
                offset *= ptrSize;

            s_entries.push_back({ static_cast<std::uint32_t>(offset), static_cast<std::uint32_t>(id) });
            prevID     = id;
            prevOffset = offset;
        }
        return true;
    }

    // ------------------------------------------------------------------------
    // v5 (Starfield): a flat uint32 array indexed directly by ID, value = byte
    // offset (0 = unused). We invert it into offset-sorted (offset, id) pairs.
    // ------------------------------------------------------------------------
    static bool LoadV5(std::ifstream& in, std::uint32_t count)
    {
        if (count == 0 || count > kMaxCount)
            return false;

        std::vector<std::uint32_t> offsets(count);
        if (!in.read(reinterpret_cast<char*>(offsets.data()),
                     static_cast<std::streamsize>(count) * sizeof(std::uint32_t)))
            return false;

        s_entries.clear();
        s_entries.reserve(count);
        for (std::uint32_t id = 0; id < count; ++id) {
            if (offsets[id] != 0)
                s_entries.push_back({ offsets[id], id });
        }
        return !s_entries.empty();
    }

    static std::filesystem::path PluginsDir()
    {
        wchar_t exe[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        return std::filesystem::path(exe).parent_path() / "Data" / "SFSE" / "Plugins";
    }

    // Try one candidate file; returns true only if its header version matches the
    // running game and its body parses.
    static bool TryLoad(const std::filesystem::path& path, const Version& gameVer)
    {
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (!in)
            return false;

        std::uint32_t format = 0;
        std::uint32_t gv[4]{};
        if (!Read(in, format) || !Read(in, gv[0]) || !Read(in, gv[1]) ||
            !Read(in, gv[2]) || !Read(in, gv[3]))
            return false;

        const Version dbVer{ static_cast<std::uint16_t>(gv[0]), static_cast<std::uint16_t>(gv[1]),
                             static_cast<std::uint16_t>(gv[2]), static_cast<std::uint16_t>(gv[3]) };
        if (dbVer != gameVer)
            return false;

        bool ok = false;
        if (format == 1 || format == 2) {
            std::uint32_t nameLen = 0;
            if (!Read(in, nameLen) || nameLen > 4096)
                return false;
            in.ignore(nameLen);
            std::int32_t ptrSize = 0, count = 0;
            if (!Read(in, ptrSize) || !Read(in, count) || ptrSize <= 0 || count <= 0)
                return false;
            ok = LoadV2(in, static_cast<std::uint64_t>(ptrSize), static_cast<std::uint32_t>(count));
        } else if (format == 5) {
            char         name[64]{};
            std::int32_t ptrSize = 0, dataFormat = 0, count = 0;
            if (!in.read(name, sizeof(name)) || !Read(in, ptrSize) ||
                !Read(in, dataFormat) || !Read(in, count) || count <= 0)
                return false;
            ok = LoadV5(in, static_cast<std::uint32_t>(count));
        } else {
            return false;
        }

        if (ok)
            s_dbVersion = VersionText(dbVer);
        return ok;
    }

    // ------------------------------------------------------------------------
    void Init()
    {
        try {
            CaptureGameModule();

            Version gameVer{};
            if (!GetGameVersion(gameVer)) {
                REX::WARN("AddressLibrary: could not determine game version.");
                return;
            }
            s_gameVersion = VersionText(gameVer);

            std::error_code ec;
            const auto dir = PluginsDir();
            for (std::filesystem::directory_iterator it(dir, ec), end; it != end && !ec; it.increment(ec)) {
                if (!it->is_regular_file(ec))
                    continue;
                const auto name = it->path().filename().string();
                if (name.size() < 4 ||
                    _strnicmp(name.c_str(), "versionlib", 10) != 0 ||
                    _stricmp(name.c_str() + name.size() - 4, ".bin") != 0)
                    continue;

                if (TryLoad(it->path(), gameVer)) {
                    std::sort(s_entries.begin(), s_entries.end(),
                        [](const Entry& a, const Entry& b) { return a.offset < b.offset; });
                    s_available = s_gameBase != 0 && !s_entries.empty();
                    break;
                }
            }

            if (s_available)
                REX::INFO("AddressLibrary: loaded {} ({} ids).", s_dbVersion, s_entries.size());
            else
                REX::INFO("AddressLibrary: no matching versionlib for game {} — IDs disabled.", s_gameVersion);
        } catch (...) {
            s_available = false;
            s_entries.clear();
        }
    }

    bool Available()
    {
        return s_available;
    }

    std::string Status()
    {
        if (s_available)
            return std::format("versionlib {} ({} ids)", s_dbVersion, s_entries.size());
        return std::format("not loaded (game {})", s_gameVersion.empty() ? "unknown" : s_gameVersion);
    }

    std::optional<Result> Resolve(std::uint64_t address)
    {
        if (!s_available || address < s_gameBase || address >= s_gameBase + s_gameSize)
            return std::nullopt;

        const auto off = static_cast<std::uint32_t>(address - s_gameBase);

        // Greatest entry whose offset is <= off.
        auto it = std::upper_bound(s_entries.begin(), s_entries.end(), off,
            [](std::uint32_t o, const Entry& e) { return o < e.offset; });
        if (it == s_entries.begin())
            return std::nullopt;
        --it;

        const std::uint64_t disp = off - it->offset;
        if (disp > kMaxDisplacement)
            return std::nullopt;
        return Result{ it->id, disp };
    }
}
