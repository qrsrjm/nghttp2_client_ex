# ------------------------------------------------------------------------------
#   Author: Reed P Morrison
#   Date:   02/20/2016
# ------------------------------------------------------------------------------
# Project setup
project(nghttp2_client_ex)
cmake_minimum_required(VERSION 2.8.0)

# Build options
option(GCC_OPTIONS      "Command line options passed to gcc or 'native' to compile for this hardware" OFF)
option(FORTIFY          "Fortify Source GCC options" OFF)
option(DEBUG_MODE       "Compile in debug mode." OFF)
option(BUILD_SYMBOLS    "Build with Symbols" ON)

# ------------------------------------------------------------------------------
# Compiler options
# ------------------------------------------------------------------------------
#add_definitions(-std=c++0x)
#add_definitions(-Wall -Werror -Weffc++ -Wformat -Wformat-security)
#add_definitions(-pedantic)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  # using GCC
  add_definitions(-D_U_=__attribute__\(\(unused\)\))
endif()

# ------------------------------------------------------------------------------
# Libraries options
# ------------------------------------------------------------------------------
#set(LIBRARIES ${LIBRARIES} pthread rt)

# ------------------------------------------------------------------------------
# Display the current settings
# ------------------------------------------------------------------------------
message(STATUS "Build Configuration:")
message("")
message("    Build Option                               Variable                Value                 ")
message("    ------------------------------------------------------------------------------------------")
message("    Debug mode:                                " "DEBUG_MODE              " ${DEBUG_MODE})
message("    Build Symbols                              " "BUILD_SYMBOLS           " ${BUILD_SYMBOLS})
message("")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
set(LIBRARIES ${LIBRARIES} dl)
message(STATUS "Libraries: ${LIBRARIES}")

# ------------------------------------------------------------------------------
# Optional flags
# ------------------------------------------------------------------------------
if (DEBUG_MODE)
  add_definitions(-O0 -ggdb)
else()
  add_definitions(-O2)
endif()
if (BUILD_SYMBOLS)
  add_definitions(-ggdb)
endif()

# ------------------------------------------------------------------------------
# include source and test directories
# ------------------------------------------------------------------------------
add_subdirectory(src)
