find_package(ClangTools)
# clang-tidy uses the compile_commands.json file for include dirs and other config
add_custom_target(clang-tidy ${CLANG_TIDY_PROGRAM}
                  -p=compile_commands.json
                  -format-style=file
                  --
                  ${lib_sources}
                  DEPENDS ${lib_sources}
                  COMMENT "Run clang-tidy on the library")
add_dependencies(clang-tidy opcua)
set_target_properties(clang-tidy PROPERTIES FOLDER "CodeAnalysis")

add_custom_target(cpplint cpplint
                  ${lib_sources}
                  ${internal_headers}
                  ${default_plugin_headers}
                  ${default_plugin_sources}
                  ${ua_architecture_headers}
                  ${ua_architecture_sources}
                  DEPENDS ${lib_sources}
                          ${internal_headers}
                          ${default_plugin_headers}
                          ${default_plugin_sources}
                          ${ua_architecture_headers}
                          ${ua_architecture_sources}
                  COMMENT "Run cpplint code style checker on the library")
set_target_properties(cpplint PROPERTIES FOLDER "CodeAnalysis")


# adds new target "clang-format" to enforce clang-format rules
find_program(CLANG_FORMAT_EXE NAMES "clang-format")
if(CLANG_FORMAT_EXE)
    file(GLOB_RECURSE FILES_TO_FORMAT
