################################################################################
#
# The main toxcore CMake build file.
#
# This file when processed with cmake produces:
# - A number of small libraries (.a/.so/...) containing independent components
#   of toxcore. E.g. the DHT has its own library, and the system/network
#   abstractions are in their own library as well. These libraries are not
#   installed on `make install`. The toxav, and toxencryptsave libraries are
#   also not installed.
# - A number of small programs, statically linked if possible.
# - One big library containing all of the toxcore, toxav, and toxencryptsave
#   code.
#
################################################################################

cmake_minimum_required(VERSION 2.8.12)
cmake_policy(VERSION 2.8.12)
project(toxcore)

list(APPEND CMAKE_MODULE_PATH ${toxcore_SOURCE_DIR}/cmake)

option(FLAT_OUTPUT_STRUCTURE "Whether to produce output artifacts in ${CMAKE_BINARY_DIR}/{bin,lib}" OFF)
if(FLAT_OUTPUT_STRUCTURE)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

set_source_files_properties(
  toxcore/mono_time.c
  toxcore/network.c
  toxcore/tox.c
  toxcore/util.c
  PROPERTIES SKIP_UNITY_BUILD_INCLUSION TRUE)

################################################################################
#
# :: Version management
#
################################################################################

# This version is for the entire project. All libraries (core, av, ...) move in
# versions in a synchronised way.
set(PROJECT_VERSION_MAJOR "0")
set(PROJECT_VERSION_MINOR "2")
set(PROJECT_VERSION_PATCH "18")
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

# set .so library version / following libtool scheme
# https://www.gnu.org/software/libtool/manual/libtool.html#Updating-version-info
file(STRINGS ${toxcore_SOURCE_DIR}/so.version SOVERSION_CURRENT REGEX "^CURRENT=[0-9]+$")
string(SUBSTRING "${SOVERSION_CURRENT}" 8 -1 SOVERSION_CURRENT)
file(STRINGS ${toxcore_SOURCE_DIR}/so.version SOVERSION_REVISION REGEX "^REVISION=[0-9]+$")
string(SUBSTRING "${SOVERSION_REVISION}" 9 -1 SOVERSION_REVISION)
file(STRINGS ${toxcore_SOURCE_DIR}/so.version SOVERSION_AGE REGEX "^AGE=[0-9]+$")
string(SUBSTRING "${SOVERSION_AGE}" 4 -1 SOVERSION_AGE)
# account for some libtool magic, see other/version-sync script for details
math(EXPR SOVERSION_MAJOR ${SOVERSION_CURRENT}-${SOVERSION_AGE})
set(SOVERSION "${SOVERSION_MAJOR}.${SOVERSION_AGE}.${SOVERSION_REVISION}")
message("SOVERSION: ${SOVERSION}")

################################################################################
#
# :: Dependencies and configuration
#
################################################################################

include(CTest)
include(ModulePackage)
include(StrictAbi)
include(GNUInstallDirs)

if(APPLE)
  include(MacRpath)
endif()

enable_testing()

set(CMAKE_MACOSX_RPATH ON)

if(${CMAKE_VERSION} VERSION_LESS "3.1.0")
  if(NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
  endif()
else()
  # Set standard version for compiler.
  set(CMAKE_C_STANDARD 99)
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_C_EXTENSIONS OFF)
  set(CMAKE_CXX_EXTENSIONS OFF)

  message(STATUS "Supported C compiler features = ${CMAKE_C_COMPILE_FEATURES}")
  message(STATUS "Supported C++ compiler features = ${CMAKE_CXX_COMPILE_FEATURES}")
endif()

set(MIN_LOGGER_LEVEL "" CACHE STRING "Logging level to use (TRACE, DEBUG, INFO, WARNING, ERROR)")
if(MIN_LOGGER_LEVEL)
  if(("${MIN_LOGGER_LEVEL}" STREQUAL "TRACE") OR
     ("${MIN_LOGGER_LEVEL}" STREQUAL "DEBUG") OR
     ("${MIN_LOGGER_LEVEL}" STREQUAL "INFO") OR
     ("${MIN_LOGGER_LEVEL}" STREQUAL "WARNING") OR
     ("${MIN_LOGGER_LEVEL}" STREQUAL "ERROR"))
    add_definitions(-DMIN_LOGGER_LEVEL=LOGGER_LEVEL_${MIN_LOGGER_LEVEL})
  else()
    message(FATAL_ERROR "Unknown value provided for MIN_LOGGER_LEVEL: \"${MIN_LOGGER_LEVEL}\", must be one of TRACE, DEBUG, INFO, WARNING or ERROR")
  endif()
endif()

option(USE_IPV6 "Use IPv6 in tests" ON)
if(NOT USE_IPV6)
  add_definitions(-DUSE_IPV6=0)
endif()

option(USE_TEST_NETWORK "Use a separate test network with different packet IDs" OFF)
if(USE_TEST_NETWORK)
  add_definitions(-DUSE_TEST_NETWORK=1)
endif()

option(BUILD_MISC_TESTS "Build additional tests and utilities" OFF)
option(BUILD_FUN_UTILS "Build additional just for fun utilities" OFF)

option(AUTOTEST "Enable autotests (mainly for CI)" OFF)
if (AUTOTEST)
  option(NON_HERMETIC_TESTS "Whether to build and run tests that depend on an internet connection" OFF)
  option(PROXY_TEST "Enable proxy test (needs HTTP/SOCKS5 proxy on port 8080/8081)" OFF)
endif()

option(BUILD_TOXAV "Whether to build the tox AV library" ON)
option(MUST_BUILD_TOXAV "Fail the build if toxav cannot be built" OFF)

option(DHT_BOOTSTRAP "Enable building of DHT_bootstrap" ON)
option(BOOTSTRAP_DAEMON "Enable building of tox-bootstrapd" ON)
if(BOOTSTRAP_DAEMON AND WIN32)
  message(WARNING "Building tox-bootstrapd for Windows is not supported, disabling")
  set(BOOTSTRAP_DAEMON OFF)
endif()

# Enabling this breaks all other tests and no network connections will be possible
option(BUILD_FUZZ_TESTS "Build fuzzing harnesses" OFF)
if(BUILD_FUZZ_TESTS)
    message(STATUS "Building in fuzz testing mode, no network connection will be possible")
    # Disable everything we can
    set(AUTOTEST OFF)
    set(BUILD_MISC_TESTS OFF)
    set(BUILD_FUN_UTILS OFF)
    set(ENABLE_SHARED OFF)
    set(MUST_BUILD_TOXAV OFF)
    set(BUILD_TOXAV OFF)
    set(BOOTSTRAP_DAEMON OFF)
    set(DHT_BOOTSTRAP OFF)
endif()


if(MSVC)
  option(MSVC_STATIC_SODIUM "Whether to link libsodium statically for MSVC" OFF)
  if(MSVC_STATIC_SODIUM)
    add_definitions(-DSODIUM_STATIC=1 -DSODIUM_EXPORT)
  endif()
endif()

include(Dependencies)

if(MUST_BUILD_TOXAV)
  set(NO_TOXAV_ERROR_TYPE SEND_ERROR)
else()
  set(NO_TOXAV_ERROR_TYPE WARNING)
endif()

if(BUILD_TOXAV)
  if(NOT OPUS_FOUND)
    message(${NO_TOXAV_ERROR_TYPE} "Option BUILD_TOXAV is enabled but required library OPUS was not found.")
    set(BUILD_TOXAV OFF)
  endif()
  if(NOT VPX_FOUND)
    message(${NO_TOXAV_ERROR_TYPE} "Option BUILD_TOXAV is enabled but required library VPX was not found.")
    set(BUILD_TOXAV OFF)
  endif()
endif()

# Disable float/double packing in CMP (C MessagePack library).
# We don't transfer floats over the network, so we disable this functionality.
add_definitions(-DCMP_NO_FLOAT=1)

################################################################################
#
# :: Tox Core Library
#
################################################################################

# toxcore_PKGCONFIG_LIBS is what's added to the Libs: line in toxcore.pc. It
# needs to contain all the libraries a program using toxcore should link against
# if it's statically linked. If it's dynamically linked, there is no need to
# explicitly link against all the dependencies, but it doesn't harm much(*)
# either.
#
# (*) It allows client code to use symbols from our dependencies without
#    explicitly linking against them.
set(toxcore_PKGCONFIG_LIBS)
# Requires: in pkg-config file.
set(toxcore_PKGCONFIG_REQUIRES)

set(toxcore_SOURCES
  third_party/cmp/cmp.c
  third_party/cmp/cmp.h
  toxcore/announce.c
  toxcore/announce.h
  toxcore/bin_pack.c
  toxcore/bin_pack.h
  toxcore/bin_unpack.c
  toxcore/bin_unpack.h
  toxcore/ccompat.c
  toxcore/ccompat.h
  toxcore/crypto_core.c
  toxcore/crypto_core.h
  toxcore/DHT.c
  toxcore/DHT.h
  toxcore/events/conference_connected.c
  toxcore/events/conference_invite.c
  toxcore/events/conference_message.c
  toxcore/events/conference_peer_list_changed.c
  toxcore/events/conference_peer_name.c
  toxcore/events/conference_title.c
  toxcore/events/events_alloc.c
  toxcore/events/events_alloc.h
  toxcore/events/file_chunk_request.c
  toxcore/events/file_recv.c
  toxcore/events/file_recv_chunk.c
  toxcore/events/file_recv_control.c
  toxcore/events/friend_connection_status.c
  toxcore/events/friend_lossless_packet.c
  toxcore/events/friend_lossy_packet.c
  toxcore/events/friend_message.c
  toxcore/events/friend_name.c
  toxcore/events/friend_read_receipt.c
  toxcore/events/friend_request.c
  toxcore/events/friend_status.c
  toxcore/events/friend_status_message.c
  toxcore/events/friend_typing.c
  toxcore/events/self_connection_status.c
  toxcore/forwarding.c
  toxcore/forwarding.h
  toxcore/friend_connection.c
  toxcore/friend_connection.h
  toxcore/friend_requests.c
  toxcore/friend_requests.h
  toxcore/group.c
  toxcore/group_chats.c
  toxcore/group_chats.h
  toxcore/group_common.h
  toxcore/group_connection.c
  toxcore/group_connection.h
  toxcore/group.h
  toxcore/group_announce.c
  toxcore/group_announce.h
  toxcore/group_moderation.c
  toxcore/group_moderation.h
  toxcore/group_onion_announce.c
  toxcore/group_onion_announce.h
  toxcore/group_pack.c
  toxcore/group_pack.h
  toxcore/LAN_discovery.c
  toxcore/LAN_discovery.h
  toxcore/list.c
  toxcore/list.h
  toxcore/logger.c
  toxcore/logger.h
  toxcore/Messenger.c
  toxcore/Messenger.h
  toxcore/mono_time.c
  toxcore/mono_time.h
  toxcore/net_crypto.c
  toxcore/net_crypto.h
  toxcore/network.c
  toxcore/network.h
  toxcore/onion_announce.c
  toxcore/onion_announce.h
  toxcore/onion.c
  toxcore/onion_client.c
  toxcore/onion_client.h
  toxcore/onion.h
  toxcore/ping_array.c
  toxcore/ping_array.h
  toxcore/ping.c
  toxcore/ping.h
  toxcore/state.c
  toxcore/state.h
  toxcore/TCP_client.c
  toxcore/TCP_client.h
  toxcore/TCP_common.c
  toxcore/TCP_common.h
  toxcore/TCP_connection.c
  toxcore/TCP_connection.h
  toxcore/TCP_server.c
  toxcore/TCP_server.h
  toxcore/timed_auth.c
  toxcore/timed_auth.h
  toxcore/tox_api.c
  toxcore/tox.c
  toxcore/tox_dispatch.c
  toxcore/tox_dispatch.h
  toxcore/tox_events.c
  toxcore/tox_events.h
  toxcore/tox.h
  toxcore/tox_private.c
  toxcore/tox_private.h
  toxcore/tox_unpack.c
  toxcore/tox_unpack.h
  toxcore/util.c
  toxcore/util.h)
set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${LIBSODIUM_LIBRARIES})
set(toxcore_PKGCONFIG_REQUIRES ${toxcore_PKGCONFIG_REQUIRES} libsodium)
set(toxcore_API_HEADERS
  ${toxcore_SOURCE_DIR}/toxcore/tox.h^tox
  ${toxcore_SOURCE_DIR}/toxcore/tox_events.h^tox
  ${toxcore_SOURCE_DIR}/toxcore/tox_dispatch.h^tox)

################################################################################
#
# :: Audio/Video Library
#
################################################################################

if(BUILD_TOXAV)
  set(toxcore_SOURCES ${toxcore_SOURCES}
    toxav/audio.c
    toxav/audio.h
    toxav/bwcontroller.c
    toxav/bwcontroller.h
    toxav/groupav.c
    toxav/groupav.h
    toxav/msi.c
    toxav/msi.h
    toxav/ring_buffer.c
    toxav/ring_buffer.h
    toxav/rtp.c
    toxav/rtp.h
    toxav/toxav.c
    toxav/toxav.h
    toxav/toxav_old.c
    toxav/video.c
    toxav/video.h)
  set(toxcore_API_HEADERS ${toxcore_API_HEADERS}
    ${toxcore_SOURCE_DIR}/toxav/toxav.h^toxav)

  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${OPUS_LIBRARIES} ${VPX_LIBRARIES})
  set(toxcore_PKGCONFIG_REQUIRES ${toxcore_PKGCONFIG_REQUIRES} opus vpx)
endif()

################################################################################
#
# :: Block encryption libraries
#
################################################################################

set(toxcore_SOURCES ${toxcore_SOURCES}
  toxencryptsave/toxencryptsave.c
  toxencryptsave/toxencryptsave.h)
set(toxcore_API_HEADERS ${toxcore_API_HEADERS}
  ${toxcore_SOURCE_DIR}/toxencryptsave/toxencryptsave.h^tox)

################################################################################
#
# :: System dependencies
#
################################################################################

# These need to come after other dependencies, since e.g. libvpx may depend on
# pthread, but doesn't list it in VPX_LIBRARIES. We're adding it here, after
# any potential libvpx linking.
message("CMAKE_THREAD_LIBS_INIT: ${CMAKE_THREAD_LIBS_INIT}")
if(CMAKE_THREAD_LIBS_INIT)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${CMAKE_THREAD_LIBS_INIT})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} ${CMAKE_THREAD_LIBS_INIT})
endif()


if(NSL_LIBRARIES)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${NSL_LIBRARIES})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} -lnsl)
endif()

if(RT_LIBRARIES)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${RT_LIBRARIES})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} -lrt)
endif()

if(SOCKET_LIBRARIES)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${SOCKET_LIBRARIES})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} -lsocket)
endif()

if(WIN32)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ws2_32 iphlpapi)
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} -lws2_32 -liphlpapi)
endif()

################################################################################
#
# :: All layers together in one library for ease of use
#
################################################################################

# Create combined library from all the sources.
add_module(toxcore ${toxcore_SOURCES})

# Link it to all dependencies.
target_link_modules(toxcore ${toxcore_LINK_MODULES})

# Make version script (on systems that support it) to limit symbol visibility.
make_version_script(toxcore ${toxcore_API_HEADERS})

# Generate pkg-config file, install library to "${CMAKE_INSTALL_LIBDIR}" and install headers to
# "${CMAKE_INSTALL_INCLUDEDIR}/tox".
install_module(toxcore DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tox)

################################################################################
#
# :: Unit tests: no networking, just pure function calls.
#
################################################################################

include(CompileGTest)

# The actual unit tests follow.
#
unit_test(toxav ring_buffer)
unit_test(toxav rtp)
unit_test(toxcore DHT)
unit_test(toxcore bin_pack)
unit_test(toxcore crypto_core)
unit_test(toxcore group_announce)
unit_test(toxcore group_moderation)
unit_test(toxcore mono_time)
unit_test(toxcore ping_array)
unit_test(toxcore tox)
unit_test(toxcore util)

add_subdirectory(testing)

################################################################################
#
# :: Automated regression tests: create a tox network and run integration tests
#
################################################################################

if(AUTOTEST)
  add_subdirectory(auto_tests)
endif()

################################################################################
#
# :: Bootstrap daemon
#
################################################################################

if(DHT_BOOTSTRAP)
  add_executable(DHT_bootstrap
    other/DHT_bootstrap.c
    other/bootstrap_node_packets.c)
  target_link_modules(DHT_bootstrap toxcore misc_tools)
  install(TARGETS DHT_bootstrap RUNTIME DESTINATION bin)
endif()

if(BOOTSTRAP_DAEMON)
  if(LIBCONFIG_FOUND)
    add_subdirectory(other/bootstrap_daemon)
  else()
    message(WARNING "Option BOOTSTRAP_DAEMON is enabled but required library LIBCONFIG was not found.")
    set(BOOTSTRAP_DAEMON OFF)
  endif()
endif()

if(BUILD_FUN_UTILS)
  add_subdirectory(other/fun)
endif()

if (BUILD_FUZZ_TESTS)
  add_subdirectory(testing/fuzzing)
endif()
