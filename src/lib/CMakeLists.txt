# ------------------------------------------------------------------------------
#   Author: Reed P Morrison
#   Date:   02/20/2016
# ------------------------------------------------------------------------------
# Project setup
project(nghttp2_client_ex)
cmake_minimum_required(VERSION 2.8.0)

# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ../../include
)

# ------------------------------------------------------------------------------
# Source files
# ------------------------------------------------------------------------------
AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} SRCS)

#SET(SRCS
#    nghttp2_buf.c
#    nghttp2_hd_huffman.c
#    nghttp2_map.c
#    nghttp2_outbound_item.c
#    nghttp2_session.c
#    nghttp2_callbacks.c
#    nghttp2_hd_huffman_data.c
#    nghttp2_mem.c
#    nghttp2_pq.c
#    nghttp2_stream.c
#    nghttp2_frame.c
#    nghttp2_helper.c
#    nghttp2_npn.c
#    nghttp2_priority_spec.c
#    nghttp2_submit.c
#    nghttp2_hd.c
#    nghttp2_http.c
#    nghttp2_option.c
#    nghttp2_queue.c
#    nghttp2_version.c
#)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------
SET(HDRS
)

# ------------------------------------------------------------------------------
# Build library
# ------------------------------------------------------------------------------
add_library(nghttp2 STATIC ${HDRS} ${SRCS})

target_link_libraries(nghttp2)

# Create symlink for libnghttp2.so.<soversion>
SET_TARGET_PROPERTIES(nghttp2
  PROPERTIES
  SOVERSION 0
)

# Add install target for the library
install(TARGETS nghttp2
  ARCHIVE DESTINATION lib
  COMPONENT Libraries
)

# Add install target for header files
install(FILES ${HDRS}
  DESTINATION include/nghttp2
  COMPONENT Headers
)

