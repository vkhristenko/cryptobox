file(GLOB SOURCES *.cpp)
add_library(cryptobox-core SHARED ${SOURCES})
target_link_libraries(cryptobox-core)

add_subdirectory(tests)
