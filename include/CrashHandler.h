#pragma once

namespace CrashHandler
{
    // Install the SEH filter, the VEH filter guard, and the termination/fail-fast
    // IAT hooks. Call once, as early as possible (PRELOAD).
    void Install();

    // Re-patch the IATs of every module loaded since Install() ran, and re-arm the
    // top-level filter. Call once all plugins are up (LOAD).
    void OnPostLoad();
}
