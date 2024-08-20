get_filename_component(VERSION_SRC_DIR ${CMAKE_CURRENT_LIST_DIR} DIRECTORY)
set(VERSION_SRC_DIR "${VERSION_SRC_DIR}/..")

find_package(Git)

function(set_opcua_version)

    # Generate a git-describe version string from Git repository tags
    if(GIT_EXECUTABLE AND NOT DEFINED opcua_VERSION)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --dirty --match "v*"
            WORKING_DIRECTORY "${VERSION_SRC_DIR}"
            OUTPUT_VARIABLE GIT_DESCRIBE_VERSION
            RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        if(NOT GIT_DESCRIBE_ERROR_CODE)
            set(opcua_VERSION ${GIT_DESCRIBE_VERSION})
        endif()
    endif()

    # Git lookup failed
    if(NOT opcua_VERSION)
        message(WARNING "Failed to determine the version from git information. Using defaults.")
        return()
    endif()

    # Set default version numbers
    set(GIT_VER_MAJOR 0)
    set(GIT_VER_MINOR 0)
    set(GIT_VER_PATCH 0)

    # Disect the version string with regexes

    STRING(REGEX REPLACE "^(v[0-9\\.]+)(.*)$"
           "\\1"
           GIT_VERSION_NUMBERS
           "${opcua_VERSION}" )

    STRING(REGEX REPLACE "^v([0-9\\.]+)(.*)$"
           "\\2"
           GIT_VERSION_LABEL
           "${opcua_VERSION}" )

    if("${GIT_VERSION_NUMBERS}" MATCHES "^v([0-9]+)(.*)$")
       STRING(REGEX REPLACE "^v([0-9]+)\\.?(.*)$"
              "\\1"
              GIT_VER_MAJOR
              "${GIT_VERSION_NUMBERS}" )

        if("${GIT_VERSION_NUMBERS}" MATCHES "^v([0-9]+)\\.([0-9]+)(.*)$")
           STRING(REGEX REPLACE "^v([0-9]+)\\.([0-9]+)(.*)$"
                  "\\2"
                  GIT_VER_MINOR
                  "${GIT_VERSION_NUMBERS}" )

           if("${GIT_VERSION_NUMBERS}" MATCHES "^v([0-9]+)\\.([0-9]+)\\.([0-9]+)(.*)$")
              STRING(REGEX REPLACE "^v([0-9]+)\\.([0-9]+)\\.([0-9]+)(.*)$"
                     "\\3"
                     GIT_VER_PATCH
                     "${GIT_VERSION_NUMBERS}" )
           endif()
       endif()
   endif()

   # Set the variables in the parent scope
   set(opcua_VER_MAJOR ${GIT_VER_MAJOR} PARENT_SCOPE)
   set(opcua_VER_MINOR ${GIT_VER_MINOR} PARENT_SCOPE)
   set(opcua_VER_PATCH ${GIT_VER_PATCH} PARENT_SCOPE)
   set(opcua_VER_LABEL "${GIT_VERSION_LABEL}" PARENT_SCOPE)
   set(opcua_VER_COMMIT ${opcua_VERSION} PARENT_SCOPE)

endfunction()
