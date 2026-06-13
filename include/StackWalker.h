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

namespace StackWalker
{
    // Walk the call stack from the given exception context.
    // Returns up to maxFrames resolved frames.
    std::vector<StackFrame> Walk(CONTEXT* ctx, std::size_t maxFrames = 128);
}
