#pragma once

// -----------------------------------------------------------------------------
// AddressLibrary — resolves a runtime address inside the game executable to a
// stable Address Library ID (the same IDs mod authors and other crash logs use),
// so "Starfield.exe+0x1A2B3C4" also reads as "ID: 449566+0x2A" — comparable
// across game versions and searchable against known crashes.
//
// The Address Library database ships as Data/SFSE/Plugins/versionlib-<ver>.bin.
// We parse it ourselves (both the delta-encoded v1/v2 format and the direct
// v5 array Starfield uses) so this stays independent of CommonLib's version-
// dependent machinery, and — unlike CommonLib's IDDB, which aborts the process
// on a missing or mismatched file — we always degrade gracefully: if no DB
// matching the running game version is found, resolution is simply disabled.
// -----------------------------------------------------------------------------

namespace AddressLibrary
{
    // Parse the matching DB, if present. Call once at plugin load. Never throws.
    void Init();

    // True if a version-matched DB was loaded.
    bool Available();

    // One-line human-readable status for the crash-log header, e.g.
    // "versionlib 1.14.70.0 (523480 ids)" or "not loaded (game 1.14.70.0)".
    std::string Status();

    struct Result
    {
        std::uint32_t id;
        std::uint64_t displacement;  // bytes past the ID's offset
    };

    // Resolve a runtime address in the game module to the nearest ID at or below
    // it. nullopt if unavailable, outside the game module, or too far from any ID.
    std::optional<Result> Resolve(std::uint64_t address);
}
