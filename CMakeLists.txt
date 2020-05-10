cmake_minimum_required(VERSION 3.8)
project (cryptobox VERSION 0.0)

# module search path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")

# add sodium
find_package(Sodium REQUIRED)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=c++17")

include_directories(${PROJECT_SOURCE_DIR}/src)

add_subdirectory(src/cryptobox)
