#pragma once

#include <cassert>
#include <cstdint>
#include <ctime>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "RE/Starfield.h"
#include "SFSE/SFSE.h"

// CommonLib wraps Win32 in REX::W32 and bans <windows.h> before its own headers.
// Include Windows API here, after CommonLib, so DbgHelp and friends get the base types.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef ERROR    // wingdi.h #defines ERROR 0; conflicts with REX::ERROR
#include <DbgHelp.h>
#include <Psapi.h>
#include <ShlObj.h>

using namespace std::literals;
