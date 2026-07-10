#pragma once

// -----------------------------------------------------------------------------
// LoadOrder — the game's content-plugin load order, read from
// %LOCALAPPDATA%\Starfield\Plugins.txt. The module list only covers loaded DLLs;
// .esm/.esp/.esl content plugins never appear there, so this is what answers
// "which content mod was active" for a crash. Version-independent (a plain file),
// captured once at plugin load, and printed into each crash report.
// -----------------------------------------------------------------------------

namespace LoadOrder
{
    struct Entry
    {
        std::string name;
        bool        enabled;  // '*'-prefixed in Plugins.txt
    };

    // Read and cache the load order. Call once at plugin load. Never throws.
    void Init();

    // True if Plugins.txt was found and read (even if it listed nothing).
    bool Available();

    // Where we looked, for the crash-log header.
    std::string SourcePath();

    const std::vector<Entry>& Entries();
}
