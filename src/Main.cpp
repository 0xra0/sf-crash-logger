#include "PCH.h"
#include "CrashHandler.h"
#include "LogWriter.h"

// SFSE_PLUGIN_PRELOAD fires before any other plugin initialises.
// Installing the crash handler here means we also catch crashes from
// plugins that load after us during SFSE's initialisation sequence.
SFSE_PLUGIN_PRELOAD(const SFSE::PreLoadInterface* a_sfse)
{
    SFSE::Init(a_sfse);
    CrashHandler::Install();
    return true;
}

SFSE_PLUGIN_LOAD(const SFSE::LoadInterface* a_sfse)
{
    SFSE::Init(a_sfse);
    LogWriter::WriteStartupLog();
    REX::INFO("CrashLogger loaded. Crash logs -> {}", LogWriter::GetLogDir().string());
    return true;
}
