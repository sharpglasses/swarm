CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(Swarm)

SET(CMAKE_CXX_FLAGS_RELEASE "-Wall -O2 -std=c++0x")
SET(CMAKE_CXX_FLAGS_DEBUG   "-Wall -O0 -std=c++0x -g")
SET(CMAKE_BUILD_TYPE Release)
SET(CMAKE_SHARED_LINKER_FLAGS "-lpcap -dynamiclib")

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

# cmake_policy(SET CMP0015 NEW)

INCLUDE_DIRECTORIES(${INC_DIR} ./src)
LINK_DIRECTORIES(${LIB_DIR})

FILE(GLOB BASESRCS "src/*.cc" "src/proto/*.cc" "src/utils/*.cc")
FILE(GLOB TESTSRCS "test/*.cc")

ADD_LIBRARY(swarm SHARED ${BASESRCS})
TARGET_LINK_LIBRARIES(swarm pcap pthread)

ADD_EXECUTABLE(swarm-test ${TESTSRCS})
TARGET_LINK_LIBRARIES(swarm-test swarm)

ADD_LIBRARY(optparse OBJECT apps/optparse.cc)

ADD_EXECUTABLE(devourer apps/devourer.cc $<TARGET_OBJECTS:optparse>)
TARGET_LINK_LIBRARIES(devourer swarm)
ADD_EXECUTABLE(dnshive apps/dnshive.cc $<TARGET_OBJECTS:optparse>)
TARGET_LINK_LIBRARIES(dnshive swarm)
ADD_EXECUTABLE(overseer apps/overseer.cc $<TARGET_OBJECTS:optparse>)
TARGET_LINK_LIBRARIES(overseer swarm)
ADD_EXECUTABLE(swarm-bench apps/swarm-bench.cc $<TARGET_OBJECTS:optparse>)
TARGET_LINK_LIBRARIES(swarm-bench swarm)
