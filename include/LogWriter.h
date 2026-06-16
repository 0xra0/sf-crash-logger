#pragma once

#include "Modules.h"
#include "RTTIReader.h"
#include "StackWalker.h"

namespace LogWriter
{
    // Returns a timestamp string suitable for use in filenames, e.g. "20260613_153045".
    // Callers should generate it once and pass it to both Write() and WriteMiniDump()
    // so the .log and .dmp files have matching names.
    std::string MakeFileTimestamp();

    std::filesystem::path GetLogDir();

    void Write(
        EXCEPTION_POINTERS*                        ep,
        const std::vector<StackFrame>&             frames,
        const std::vector<ModuleInfo>&             modules,
        const std::vector<RTTIReader::RegisterObject>& rttiObjects,
        const std::string&                         fileTimestamp);

    void WriteMiniDump(
        EXCEPTION_POINTERS*        ep,
        const std::filesystem::path& logDir,
        const std::string&           fileTimestamp);

    // Appends a "loaded" entry to CrashLogger.log in the Crashlogs directory.
    // Call once from SFSE_PLUGIN_LOAD to confirm the plugin is active each session.
    void WriteStartupLog();
}
