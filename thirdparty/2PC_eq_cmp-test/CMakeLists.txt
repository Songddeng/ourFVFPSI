cmake_minimum_required(VERSION 3.15)
project(secure_cmp_bridge LANGUAGES CXX)

set(SECURE_CMP_LIBOTE_ROOT "/home/songdengdeng/libOTe" CACHE PATH "Root of the standalone libOTe workspace used by secure_cmp")

set(SECURE_CMP_LIBOTE_BUILD_ROOT "${SECURE_CMP_LIBOTE_ROOT}/out/build/linux")
set(SECURE_CMP_LIBOTE_INSTALL_ROOT "${SECURE_CMP_LIBOTE_ROOT}/out/install/linux")

set(SECURE_CMP_REQUIRED_FILES
    "${SECURE_CMP_LIBOTE_BUILD_ROOT}/libOTe/liblibOTe.a"
    "${SECURE_CMP_LIBOTE_BUILD_ROOT}/thirdparty/SimplestOT/libSimplestOT.a"
    "${SECURE_CMP_LIBOTE_BUILD_ROOT}/cryptoTools/cryptoTools/libcryptoTools.a"
    "${SECURE_CMP_LIBOTE_BUILD_ROOT}/coproto/coproto/libcoproto.a"
    "${SECURE_CMP_LIBOTE_BUILD_ROOT}/macoro/macoro/libmacoro.a"
    "${SECURE_CMP_LIBOTE_BUILD_ROOT}/thirdparty/KyberOT/libKyberOT.a"
    "${SECURE_CMP_LIBOTE_INSTALL_ROOT}/lib/libsodium.a"
    "${SECURE_CMP_LIBOTE_INSTALL_ROOT}/lib/libboost_system.a"
    "${SECURE_CMP_LIBOTE_INSTALL_ROOT}/lib/libboost_thread.a"
)

foreach(required_file IN LISTS SECURE_CMP_REQUIRED_FILES)
    if(NOT EXISTS "${required_file}")
        message(FATAL_ERROR "secure_cmp requires standalone libOTe artifacts, missing: ${required_file}")
    endif()
endforeach()

find_package(Threads REQUIRED)

option(SECURE_CMP_BUILD_EXAMPLE "Build the bundled secure comparison example executable." OFF)
option(SECURE_CMP_BUILD_ORIGINAL_MAIN "Build the original upstream eq_cmp executable." OFF)

add_library(secure_cmp_deps INTERFACE)

target_compile_definitions(secure_cmp_deps
    INTERFACE
        BOOST_SYSTEM_NO_LIB
        BOOST_THREAD_NO_LIB
)

target_compile_options(secure_cmp_deps
    INTERFACE
        -maes
        -msse2
        -msse3
        -mssse3
        -msse4.1
        -mpclmul
        -mavx2
        -Wno-error=switch
)

target_link_options(secure_cmp_deps
    INTERFACE
        -fPIC
        -no-pie
)

target_include_directories(secure_cmp_deps
    INTERFACE
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/libOTe/.."
        "${SECURE_CMP_LIBOTE_ROOT}/libOTe/.."
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/cryptoTools/cryptoTools/.."
        "${SECURE_CMP_LIBOTE_ROOT}/cryptoTools/cryptoTools/.."
        "${SECURE_CMP_LIBOTE_INSTALL_ROOT}/include"
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/coproto/coproto/.."
        "${SECURE_CMP_LIBOTE_ROOT}/out/coproto/coproto/.."
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/macoro/macoro/.."
        "${SECURE_CMP_LIBOTE_ROOT}/out/macoro/macoro/.."
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/thirdparty/SimplestOT/.."
        "${SECURE_CMP_LIBOTE_ROOT}/thirdparty/SimplestOT/.."
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/thirdparty/KyberOT/.."
        "${SECURE_CMP_LIBOTE_ROOT}/thirdparty/KyberOT/.."
)

target_link_libraries(secure_cmp_deps
    INTERFACE
        Threads::Threads
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/libOTe/liblibOTe.a"
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/thirdparty/SimplestOT/libSimplestOT.a"
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/cryptoTools/cryptoTools/libcryptoTools.a"
        "${SECURE_CMP_LIBOTE_INSTALL_ROOT}/lib/libsodium.a"
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/coproto/coproto/libcoproto.a"
        "${SECURE_CMP_LIBOTE_INSTALL_ROOT}/lib/libboost_system.a"
        "${SECURE_CMP_LIBOTE_INSTALL_ROOT}/lib/libboost_thread.a"
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/macoro/macoro/libmacoro.a"
        "${SECURE_CMP_LIBOTE_BUILD_ROOT}/thirdparty/KyberOT/libKyberOT.a"
)

add_library(secure_cmp STATIC
    utils.cpp
    secure_cmp_bridge.cpp
)

add_library(secure_cmp::secure_cmp ALIAS secure_cmp)

target_compile_features(secure_cmp PUBLIC cxx_std_20)
target_compile_options(secure_cmp
    PRIVATE
        -Wall
        -Wfatal-errors
        -Wno-unused-variable
        -fcoroutines
        -fopenmp
)

target_include_directories(secure_cmp
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_link_libraries(secure_cmp
    PRIVATE
        secure_cmp_deps
)

if(SECURE_CMP_BUILD_EXAMPLE)
    add_executable(eq_cmp
        main.cpp
    )

    target_compile_features(eq_cmp PRIVATE cxx_std_20)
    target_compile_options(eq_cmp
        PRIVATE
            -Wall
            -Wfatal-errors
            -Wno-unused-variable
            -fcoroutines
            -fopenmp
    )

    target_link_libraries(eq_cmp PRIVATE secure_cmp secure_cmp_deps)
endif()

add_executable(secure_cmp_runner
    secure_cmp_runner.cpp
)

target_compile_features(secure_cmp_runner PRIVATE cxx_std_20)
target_compile_options(secure_cmp_runner
    PRIVATE
        -Wall
        -Wfatal-errors
        -Wno-unused-variable
        -fcoroutines
        -fopenmp
)

target_link_libraries(secure_cmp_runner PRIVATE secure_cmp secure_cmp_deps)

if(SECURE_CMP_BUILD_ORIGINAL_MAIN)
    add_executable(secure_cmp_original
        main.cpp
    )

    target_compile_features(secure_cmp_original PRIVATE cxx_std_20)
    target_compile_options(secure_cmp_original
        PRIVATE
            -Wall
            -Wfatal-errors
            -Wno-unused-variable
            -fcoroutines
            -fopenmp
    )

    target_link_libraries(secure_cmp_original PRIVATE secure_cmp secure_cmp_deps)
endif()
