#include "PCH.h"
#include "LoadOrder.h"

#include <fstream>

namespace LoadOrder
{
    static bool               s_loaded = false;
    static std::string        s_path;
    static std::vector<Entry> s_entries;

    // Strip surrounding whitespace and a leading UTF-8 BOM.
    static std::string_view Trim(std::string_view s)
    {
        constexpr std::string_view bom = "\xEF\xBB\xBF";
        if (s.starts_with(bom))
            s.remove_prefix(bom.size());
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
            s.remove_prefix(1);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
            s.remove_suffix(1);
        return s;
    }

    // Parse one Plugins.txt line. Returns nullopt for blanks and '#' comments.
    // A leading '*' marks an enabled plugin (Bethesda's convention).
    static std::optional<Entry> ParseLine(std::string_view raw)
    {
        auto line = Trim(raw);
        if (line.empty() || line.front() == '#')
            return std::nullopt;

        bool enabled = false;
        if (line.front() == '*') {
            enabled = true;
            line = Trim(line.substr(1));
            if (line.empty())
                return std::nullopt;
        }
        return Entry{ std::string(line), enabled };
    }

    // Testable core: parse a whole file's worth of text from any stream.
    static std::vector<Entry> ParseStream(std::istream& in)
    {
        std::vector<Entry> out;
        std::string        line;
        while (std::getline(in, line)) {
            if (auto e = ParseLine(line))
                out.push_back(std::move(*e));
        }
        return out;
    }

    void Init()
    {
        try {
            wchar_t* local = nullptr;
            if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &local)) ||
                !local) {
                CoTaskMemFree(local);
                return;
            }
            const std::filesystem::path path = std::filesystem::path(local) / "Starfield" / "Plugins.txt";
            CoTaskMemFree(local);

            s_path = path.string();

            std::ifstream in(path, std::ios::in | std::ios::binary);
            if (!in) {
                REX::INFO("LoadOrder: {} not found — load order omitted.", s_path);
                return;
            }

            s_entries = ParseStream(in);
            s_loaded  = true;
            REX::INFO("LoadOrder: {} plugins from {}.", s_entries.size(), s_path);
        } catch (...) {
            s_loaded = false;
            s_entries.clear();
        }
    }

    bool Available()
    {
        return s_loaded;
    }

    std::string SourcePath()
    {
        return s_path;
    }

    const std::vector<Entry>& Entries()
    {
        return s_entries;
    }
}
