# Copyright [2026] <Daniel Weber>

cmake_minimum_required(VERSION 3.10)
project(trevex)


#################
# Compile Flags #
#################

# set default build type to release if nothing else is specified
set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
    # overwrite empty build type
    set(CMAKE_BUILD_TYPE "${default_build_type}")
endif()

if(STATIC_BUILD)
    message("-- Building statically-linked binary")
endif()
if(NOT STATIC_BUILD)
    message("-- Building dynamically-linked binary")
endif()

if (ARCH STREQUAL INTEL)
    message(STATUS "Compiling for Intel processor.")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DINTEL")
elseif(ARCH STREQUAL AMD)
    message(STATUS "Compiling for AMD processor.")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DAMD")
elseif(ARCH STREQUAL ZHAOXIN)
    message(STATUS "Compiling for ZHAOXIN processor.")
    # for now we treat Zhaoxin as an Intel superset
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DINTEL -DZHAOXIN")
else()
    message(WARNING "Illegal or missing value for target processor. Set '-DARCH=[INTEL|AMD|ZHAOXIN]'. Defaulting to INTEL.")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DINTEL")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fno-stack-protector")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-variable -Wno-unused-function -Wno-unused-result")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-strict-aliasing")  # required for PTEditor

# Release Mode
set(CMAKE_CXX_FLAGS_RELEASE  "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DDEBUGMODE=0")

# Release With Debug Info Mode
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DDEBUGMODE=1 -ggdb")

# Debug Mode
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUGMODE=1")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_GLIBCXX_DEBUG") # enable debug features in libcstd++
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fsanitize=undefined")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize-recover=address")

if(STATIC_BUILD AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
endif()

################
# Dependencies #
################

include(FetchContent)

# PThread
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ASMJit
if (LOCAL_BUILD_ASMJIT)
  message(STATUS "Using local ASMJit copy")
  set(FETCHCONTENT_SOURCE_DIR_ASMJIT "${CMAKE_SOURCE_DIR}/src/external/asmjit")
else()
  message(STATUS "Fetching ASMJit from GitHub")
endif()

FetchContent_Declare(
  asmjit
  GIT_REPOSITORY https://github.com/asmjit/asmjit.git
  GIT_TAG        a63d41e80ba72f652c450d3bd6614327cde8531c
)
FetchContent_MakeAvailable(asmjit)

#####################
# Targets + Linking #
#####################

# always export compile commands for linters etc
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(trevex
  src/main.cc
  src/logger/logger.cc
  src/utils.cc
  src/core.cc
  src/executor.cc
  src/victims/kernel_victim.cc
  src/cacheutils/cacheutils.cc
  src/testcase_generator.cc
  src/external/PTEditor/ptedit.c
)

target_include_directories(trevex PRIVATE ${CMAKE_SOURCE_DIR}/src)

# we set -pendantic -Werror only for trevex but *not* for our dependencies
# cause asmjit causes too many warnings
target_compile_options(trevex PRIVATE -pedantic -Werror)

target_link_libraries(trevex PRIVATE asmjit Threads::Threads -lrt)
