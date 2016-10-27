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
    ../../ext
)

#add_definitions(-std=c++0x)

# ------------------------------------------------------------------------------
# Source files
# ------------------------------------------------------------------------------
SET(H2_CLIENT_SRCS
    ../../ext/http_parser/http_parser.cc
    support.cc
    h2_client.cc
)

SET(CLIENT_SRCS
    client.cc
)


# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------
SET(HDRS
)

# ------------------------------------------------------------------------------
# build
# ------------------------------------------------------------------------------
add_executable(client_cmd ${HDRS} ${CLIENT_SRCS})
add_dependencies(client_cmd nghttp2)
SET_TARGET_PROPERTIES(client_cmd PROPERTIES OUTPUT_NAME "client")
target_link_libraries(client_cmd ${CMAKE_BINARY_DIR}/src/lib/libnghttp2.a ${LIBRARIES})

add_executable(h2_client_cmd ${HDRS} ${H2_CLIENT_SRCS})
add_dependencies(h2_client_cmd nghttp2)
SET_TARGET_PROPERTIES(h2_client_cmd PROPERTIES OUTPUT_NAME "h2_client")
target_link_libraries(h2_client_cmd ${CMAKE_BINARY_DIR}/src/lib/libnghttp2.a ${LIBRARIES})


