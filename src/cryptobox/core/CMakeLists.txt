file(GLOB SOURCES *.cpp)
include_directories(${sodium_INCLUDE_DIR})
add_library(cryptobox-core SHARED ${SOURCES})
target_link_libraries(cryptobox-core ${sodium_LIBRARY_RELEASE} ${Boost_LIBRARIES})

add_subdirectory(tests)
