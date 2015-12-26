project (ndyndns)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -pedantic -Wall -Wextra -Wformat=2 -Wformat-security -Wpointer-arith -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++14 -pedantic -Wall -Wextra -Wformat=2 -Wformat-security -Wpointer-arith -Wno-unused-parameter")

include_directories("${PROJECT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/ncmlib")
add_subdirectory(ncmlib)

find_package(CURL)
link_directories ( ${CURL_LIBRARY_DIRS} )
include_directories ( ${CURL_INCLUDE_DIRS} )

file(GLOB NDYNDNS_SRCS "*.c")
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  message("System is Linux.")
  file(GLOB NDYNDNS_REM_SRCS "bsd.c" "sun.c")
  list(REMOVE_ITEM NDYNDNS_SRCS ${NDYNDNS_REM_SRCS})
endif()
if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  message("System is BSD.")
  file(GLOB NDYNDNS_REM_SRCS "linux.c" "sun.c")
  list(REMOVE_ITEM NDYNDNS_SRCS ${NDYNDNS_REM_SRCS})
endif()
if (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  message("System is BSD.")
  file(GLOB NDYNDNS_REM_SRCS "linux.c" "sun.c")
  list(REMOVE_ITEM NDYNDNS_SRCS ${NDYNDNS_REM_SRCS})
endif()
if (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
  message("System is BSD.")
  file(GLOB NDYNDNS_REM_SRCS "linux.c" "sun.c")
  list(REMOVE_ITEM NDYNDNS_SRCS ${NDYNDNS_REM_SRCS})
endif()

add_executable(ndyndns ${NDYNDNS_SRCS})
target_link_libraries(ndyndns ${CURL_LIBRARIES} ncmlib)

