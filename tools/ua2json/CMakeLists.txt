set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(ua2json ua2json.c)
target_link_libraries(ua2json opcua ${opcua_LIBRARIES})
assign_source_group(ua2json)
add_dependencies(ua2json opcua-object)
set_target_properties(ua2json PROPERTIES FOLDER "opcua/tools/ua2json")
set_target_properties(ua2json PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
