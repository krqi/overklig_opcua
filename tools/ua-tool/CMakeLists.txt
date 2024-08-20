set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(ua ua.c)
target_link_libraries(ua opcua ${opcua_LIBRARIES})
assign_source_group(ua-tool)
add_dependencies(ua opcua-object)
set_target_properties(ua PROPERTIES FOLDER "opcua/tools/ua-tool")
set_target_properties(ua PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
