# SPDX-License-Identifier: MIT OR Apache-2.0
cmake_minimum_required(VERSION 3.16)
project(LogosMapLibrary LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt6 6.9.2 EXACT REQUIRED COMPONENTS Core)
add_library(maps_backend SHARED
  backend/MapBackend.cpp backend/MapBackend.h backend/maps.qrc)
target_compile_definitions(maps_backend PRIVATE PRIZE_MAPS_BIN=\"\")
target_link_libraries(maps_backend PRIVATE Qt6::Core ${CMAKE_DL_LIBS})
set_target_properties(maps_backend PROPERTIES PREFIX "" OUTPUT_NAME "logos_maps_plugin")
install(TARGETS maps_backend LIBRARY DESTINATION lib)
