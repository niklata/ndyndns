project (ndyndns)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Wextra -Wno-format-extra-args -Wno-format-zero-length -Wformat-nonliteral -Wformat-security -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu99 -Wall -Wextra -Wno-format-extra-args -Wno-format-zero-length -Wformat-nonliteral -Wformat-security -pedantic")

include_directories("${PROJECT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/ncmlib")
add_subdirectory(ncmlib)

find_package(CURL)
link_directories ( ${CURL_LIBRARY_DIRS} )
include_directories ( ${CURL_INCLUDE_DIRS} )

file(GLOB NDYNDNS_SRCS "*.c")
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    file(REMOVE NDYNDNS_SRCS "sun.c")
    file(REMOVE NDYNDNS_SRCS "bsd.c")
endif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    file(REMOVE NDYNDNS_SRCS "sun.c")
    file(REMOVE NDYNDNS_SRCS "linux.c")
endif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
if (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
    file(REMOVE NDYNDNS_SRCS "sun.c")
    file(REMOVE NDYNDNS_SRCS "linux.c")
endif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
if (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
    file(REMOVE NDYNDNS_SRCS "sun.c")
    file(REMOVE NDYNDNS_SRCS "linux.c")
endif (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")

add_executable(ndyndns ${NDYNDNS_SRCS})
target_link_libraries(ndyndns ${CURL_LIBRARIES} ncmlib)

