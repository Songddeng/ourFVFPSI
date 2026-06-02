cmake_minimum_required(VERSION 3.10)
project(FPSI)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Release)

set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/thirdparty/out/install")

# secure-join in this project expects the older libOTe/cryptoTools stack that
# was built together with the local SecureJoin workspace, not the newer /usr/local one.
set(LEGACY_SECUREJOIN_ROOT "/home/songdengdeng/Desktop/SecureJoin/secure-join/out/build/linux" CACHE PATH "Compatible local SecureJoin dependency stack root")
list(PREPEND CMAKE_PREFIX_PATH
  "${CMAKE_SOURCE_DIR}/thirdparty/out/install"
  "${LEGACY_SECUREJOIN_ROOT}/../install/linux"
  "${LEGACY_SECUREJOIN_ROOT}/macoro/macoro"
  "${LEGACY_SECUREJOIN_ROOT}/coproto/coproto"
  "${LEGACY_SECUREJOIN_ROOT}/libOTe/cryptoTools"
  "${LEGACY_SECUREJOIN_ROOT}/libOTe"
)
set(SECUREJOIN_INCLUDE_ROOT "${CMAKE_SOURCE_DIR}/thirdparty/out/install/include" CACHE PATH "Include root containing the secure-join directory")
set(SECUREJOIN_GENERATED_INCLUDE_ROOT "${CMAKE_SOURCE_DIR}/thirdparty/out/install/include" CACHE PATH "Include root containing generated secure-join headers such as secure-join/config.h")
set(SECUREJOIN_LIBRARY "${CMAKE_SOURCE_DIR}/thirdparty/out/install/lib/libsecureJoin.a" CACHE FILEPATH "Path to libsecureJoin.a")
option(FPSI_ENABLE_SECURE_CMP_EXAMPLE "Build the standalone secure comparison integration example." ON)
set(SECURE_CMP_BUILD_ORIGINAL_MAIN ON CACHE BOOL "Build upstream secure comparison main executable." FORCE)
include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/thirdparty/out/install/include)

if(NOT TARGET sparsehash)
  add_library(sparsehash INTERFACE IMPORTED)
  set_target_properties(sparsehash PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/thirdparty/out/install/include"
  )
endif()

if(NOT TARGET libdivide)
  add_library(libdivide INTERFACE IMPORTED)
  set_target_properties(libdivide PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include"
  )
endif()

add_subdirectory(thirdparty/2PC_eq_cmp-test EXCLUDE_FROM_ALL)

file(GLOB SOURCES src/*.cpp)

add_executable(fpsi ${SOURCES})

# secureJoin
target_include_directories(fpsi PRIVATE ${SECUREJOIN_INCLUDE_ROOT})
target_include_directories(fpsi PRIVATE ${SECUREJOIN_GENERATED_INCLUDE_ROOT})

# Dependencies
find_package(Threads REQUIRED)
find_package(Boost 1.84.0 REQUIRED COMPONENTS system thread regex)
find_package(function2 REQUIRED)
find_package(coproto REQUIRED)
find_package(cryptoTools REQUIRED)
find_package(libOTe REQUIRED)
find_package(volePSI REQUIRED)
find_package(fmt REQUIRED)

target_link_libraries(fpsi PRIVATE oc::cryptoTools oc::libOTe visa::volePSI fmt::fmt)
target_link_libraries(fpsi PRIVATE ${SECUREJOIN_LIBRARY})
target_include_directories(fpsi PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty/2PC_eq_cmp-test)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i.86")
  target_compile_options(fpsi PRIVATE -mpclmul -maes -msse2 -msse4.1)
endif()

add_definitions(-DNDEBUG)

if(FPSI_ENABLE_SECURE_CMP_EXAMPLE)
  add_executable(test_secure_cmp tests/test_secure_cmp.cpp)
  target_link_libraries(test_secure_cmp PRIVATE secure_cmp::secure_cmp secure_cmp_deps)
  target_include_directories(test_secure_cmp PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty/2PC_eq_cmp-test)

  if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i.86")
    target_compile_options(test_secure_cmp PRIVATE -mpclmul -maes -msse2 -msse4.1)
  endif()
endif()
