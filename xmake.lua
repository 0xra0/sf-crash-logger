-- include subprojects (git submodules)
includes("lib/commonlibsf")

-- project
set_project("CrashLogger")
set_version("0.1.0")
set_license("GPL-3.0")
set_languages("c++23")
set_warnings("allextra")
set_encodings("utf-8")

-- build modes
add_rules("mode.debug", "mode.releasedbg")
add_rules("plugin.vsxmake.autoupdate")

target("CrashLogger")
    add_rules("commonlibsf.plugin", {
        name        = "CrashLogger",
        author      = "YourName",
        description = "Starfield crash logger with detailed stack traces",
        -- We use no game addresses or struct offsets, so we are fully
        -- version-independent. RUNTIME_LATEST will cover the current game
        -- version automatically after each CommonLibSF update.
        options = {
            no_struct_use    = true,   -- HasNoStructUse(true)
            address_library  = false,  -- UsesAddressLibrary(false)
            -- layout_dependent is auto-set to false by no_struct_use
        }
    })

    -- source files
    add_files("src/**.cpp")
    add_headerfiles("include/**.h")
    add_includedirs("include")
    set_pcxxheader("include/PCH.h")

    -- Windows system libraries required for DbgHelp, version info, shell
    add_syslinks("DbgHelp", "Version", "Shell32", "Ole32")
