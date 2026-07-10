#pragma once

#include "Modules.h"
#include "StackWalker.h"

// -----------------------------------------------------------------------------
// CrashSignature — a short, stable identifier for *this kind of crash*, so two
// users can tell whether they hit the same bug, and duplicate reports can be
// grouped without a human reading two stack traces side by side.
//
// The trick is what the hash is computed over. Raw addresses move with every game
// patch, so a signature built on them splinters one bug into a different value per
// game version — useless for exactly the comparison it exists to support. Because
// AddressLibrary already resolves game addresses to version-stable IDs, hashing
// those IDs instead yields a signature that survives game updates.
//
// It follows that a game address with no ID cannot be hashed: it would contribute
// a raw, version-specific offset. Rather than emit a value that silently means
// something different on each machine, the signature is withheld and says why —
// the same way IDs are simply omitted when no database matches.
//
// Addresses outside the game executable are hashed as `module+offset`, which is
// stable for a given build of that module and independent of the game version.
// -----------------------------------------------------------------------------

namespace CrashSignature
{
    struct Result
    {
        bool                     available{};
        std::string              value;    // "8C1D4E77" when available
        std::string              reason;   // why not, when unavailable
        std::vector<std::string> inputs;   // the exact tokens hashed, for auditing
    };

    // `accessOp` is EXCEPTION_RECORD::ExceptionInformation[0] for access
    // violations (0 read, 1 write, 8 execute), or nullopt for other exceptions.
    // Never throws. Safe on the crash path.
    Result Compute(std::uint32_t                   exceptionCode,
                   std::optional<std::uint32_t>    accessOp,
                   const std::vector<StackFrame>&  frames,
                   const std::vector<ModuleInfo>&  modules);
}
