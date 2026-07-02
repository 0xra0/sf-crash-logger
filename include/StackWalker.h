#pragma once

struct StackFrame
{
    std::uint64_t address{};
    std::string   moduleName;
    std::uint64_t moduleBase{};
    std::string   symbolName;
    std::uint64_t symbolDisplacement{};
    std::string   sourceFile;
    std::uint32_t sourceLine{};
};

// A pointer-sized value found while linearly scanning raw stack memory.
struct ScannedValue
{
    std::uint64_t stackAddress{};  // where on the stack the value was read
    std::uint64_t value{};         // the pointer-like value stored there
};

namespace StackWalker
{
    // Walk the call stack from the given exception context.
    // Returns up to maxFrames resolved frames.
    std::vector<StackFrame> Walk(CONTEXT* ctx, std::size_t maxFrames = 128);

    // Linearly scan the crashing thread's stack (from RSP upward) for
    // pointer-sized values. This recovers return addresses and object pointers
    // that the strict frame-based unwinder (Walk) drops when unwind data is
    // missing or the frame chain is broken — which is common in optimised
    // game/engine code. Callers resolve each value against the module list and
    // RTTI to tell return addresses from live objects.
    std::vector<ScannedValue> ScanStack(const CONTEXT* ctx, std::size_t maxBytes = 0x2000);
}
