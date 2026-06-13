#pragma once

#include <cassert>
#include <cstdint>
#include <ctime>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
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

// DbgHelp must follow Windows.h (already pulled in by RE/Starfield.h)
#include <DbgHelp.h>
#include <Psapi.h>
#include <ShlObj.h>

using namespace std::literals;
