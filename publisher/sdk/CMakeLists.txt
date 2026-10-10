# SPDX-License-Identifier: MIT OR Apache-2.0
cmake_minimum_required(VERSION 3.16)
project(PrizeMaps LANGUAGES CXX)
# Official release build. The explicit development path below remains available.
if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
  include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
  logos_module(NAME prize_maps SOURCES MapsModule.h MapsModule.cpp
    INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
    EXTERNAL_LIBS logos_maps_v03_sdk)
  return()
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 6.9.2 EXACT REQUIRED COMPONENTS Core RemoteObjects)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
foreach(required SDK_ROOT PROTOCOL_ROOT QT_HOST_ROOT HOST_BUILD GENERATED_DIR RUST_LIBRARY)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "Set ${required} to the pinned dependency/build path")
  endif()
endforeach()
add_library(prize_maps MODULE
  MapsModule.cpp
  "${GENERATED_DIR}/prize_maps_module_impl.cpp"
  "${GENERATED_DIR}/prize_maps_cdylib_glue.cpp"
  "${GENERATED_DIR}/prize_maps_cdylib_glue.h"
  "${GENERATED_DIR}/logos_sdk.cpp")
target_include_directories(prize_maps PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}" "${GENERATED_DIR}"
  "${SDK_ROOT}/cpp" "${PROTOCOL_ROOT}/cpp"
  "${QT_HOST_ROOT}/cpp" "${QT_HOST_ROOT}/core")
target_link_libraries(prize_maps PRIVATE
  "${RUST_LIBRARY}"
  "${HOST_BUILD}/lib/liblogos_qt_host.a"
  "${HOST_BUILD}/lib/liblogos_protocol.a"
  Qt6::Core Qt6::RemoteObjects OpenSSL::SSL OpenSSL::Crypto
  nlohmann_json::nlohmann_json)
set_target_properties(prize_maps PROPERTIES PREFIX "" BUILD_WITH_INSTALL_RPATH TRUE INSTALL_RPATH "$ORIGIN")
