cmake_minimum_required(VERSION 3.5)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../../ ${CMAKE_BINARY_DIR}/lib)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

get_target_property(opcua_SOURCES opcua-object SOURCES)
get_target_property(opcua_INCLUDES opcua-object INCLUDE_DIRECTORIES)

# Create an opcua component for ESP IDF
set(opcua_component_dir ${CMAKE_CURRENT_LIST_DIR}/components/opcua-lib)
file(MAKE_DIRECTORY ${opcua_component_dir})
file(WRITE ${opcua_component_dir}/CMakeLists.txt "
set(COMPONENT_SRCS ${opcua_SOURCES})
set(COMPONENT_ADD_INCLUDEDIRS ${opcua_INCLUDES})
set(COMPONENT_REQUIRES lwip mbedtls freertos)
register_component()
")

add_definitions(-DUA_ARCHITECTURE_FREERTOSLWIP)

project(hello-world)

add_dependencies(opcua-lib opcua-code-generation)

