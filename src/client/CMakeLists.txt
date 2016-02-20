# ------------------------------------------------------------------------------
#   Author: Reed P Morrison
#   Date:   02/20/2016
# ------------------------------------------------------------------------------
# Project setup
project(nghttp2_client_ex)
cmake_minimum_required(VERSION 2.8.0)

# ------------------------------------------------------------------------------
# header files to install
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})

# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR}
#${CMAKE_CURRENT_BINARY_DIR}
    ../../include
    ../lib/
)

#add_definitions(-std=c++0x)

# ------------------------------------------------------------------------------
# Source files
# ------------------------------------------------------------------------------
SET(SRCS
  nghttp2_client_ex.cc
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------
SET(HDRS
)

# ------------------------------------------------------------------------------
# build
# ------------------------------------------------------------------------------
add_executable(nghttp2_client_ex_cmd ${HDRS} ${SRCS})
add_dependencies(nghttp2_client_ex_cmd nghttp2)
SET_TARGET_PROPERTIES(nghttp2_client_ex_cmd PROPERTIES OUTPUT_NAME "nghttp2_client_ex")
target_link_libraries(nghttp2_client_ex_cmd ${CMAKE_BINARY_DIR}/src/lib/libnghttp2.a ${LIBRARIES})
