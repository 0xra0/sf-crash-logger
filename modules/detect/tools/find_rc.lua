-- Project-local override of find_rc so it works on Linux with llvm-rc (xmake cross-compile)
import("lib.detect.find_program")
import("lib.detect.find_programver")

function main(opt)
    opt = opt or {}
    opt.check   = opt.check or "-?"
    opt.command = opt.command or "-?"
    opt.parse   = opt.parse or function (output) return output:match("(%d+%.%d+%.%d+)") end

    -- table.wrap converts nil/string/table to a table safely
    opt.paths = table.wrap(opt.paths)
    table.insert(opt.paths, "/home/home/.vsxwin/bin/x64")

    local program = find_program(opt.program or "rc.exe", opt)
    local version = nil
    if program and opt and opt.version then
        version = find_programver(program, opt)
    end
    return program, version
end
