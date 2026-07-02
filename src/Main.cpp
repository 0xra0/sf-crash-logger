#include "PCH.h"
#include "Breadcrumbs.h"
#include "CrashHandler.h"
#include "LogWriter.h"

// SFSE_PLUGIN_PRELOAD fires before any other plugin initialises.
// Installing the crash handler here means we also catch crashes from
// plugins that load after us during SFSE's initialisation sequence.
SFSE_PLUGIN_PRELOAD(const SFSE::PreLoadInterface* a_sfse)
{
    SFSE::Init(a_sfse);
    Breadcrumbs::Init();          // early trace + first-chance logger, before anything can crash
    CrashHandler::Install();
    Breadcrumbs::Log("crash handler installed (preload)");
    return true;
}

SFSE_PLUGIN_LOAD(const SFSE::LoadInterface* a_sfse)
{
    SFSE::Init(a_sfse);
    LogWriter::WriteStartupLog();
    Breadcrumbs::Log("plugin load complete — game running");
    REX::INFO("CrashLogger loaded. Crash logs -> {}", LogWriter::GetLogDir().string());
    return true;
}
