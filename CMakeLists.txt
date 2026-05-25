cmake_minimum_required(VERSION 3.5.1)

project(ckkseif CXX)
set(CMAKE_CXX_STANDARD 17)
option(BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenFHE CONFIG REQUIRED)
if(OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE include files location: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE lib files location: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else()
    message(FATAL_ERROR "PACKAGE OpenFHE NOT FOUND")
endif()

set(CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS})

include_directories(${OPENMP_INCLUDES})
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)
include_directories(${OpenFHE_INCLUDE}/binfhe)

# Project headers - bare-filename includes resolve via these dirs.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/core/include/ckkseif)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/modules/helut/include/ckkseif/helut)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/modules/hecount/include/ckkseif/hecount)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/modules/parity/include/ckkseif/parity)

link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})
set(CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
link_libraries(${OpenFHE_SHARED_LIBRARIES})

# ----------------------------------------------------------------------------
# Per-module object libraries
# ----------------------------------------------------------------------------
add_library(ckkseif_core OBJECT
    core/src/eif.cpp
    core/src/arithmetic.cpp
    core/src/utils.cpp
)

add_library(ckkseif_helut OBJECT
    modules/helut/src/embedding.cpp
    modules/helut/src/lookup.cpp
)

add_library(ckkseif_hecount OBJECT
    modules/hecount/src/counting.cpp
)

add_library(ckkseif_parity OBJECT
    modules/parity/src/parity.cpp
)

# Test-routine object libraries (one per app + core).
add_library(ckkseif_core_tests OBJECT
    core/tests/test_core.cpp
    core/src/bench_runner.cpp
)

add_library(ckkseif_helut_tests OBJECT
    modules/helut/tests/test_helut.cpp
)

add_library(ckkseif_hecount_tests OBJECT
    modules/hecount/tests/test_count.cpp
)

add_library(ckkseif_parity_tests OBJECT
    modules/parity/tests/test_parity.cpp
)

# ----------------------------------------------------------------------------
# Per-app executables
# ----------------------------------------------------------------------------
add_executable(bench_core
    core/exp/main_core.cpp
    $<TARGET_OBJECTS:ckkseif_core>
    $<TARGET_OBJECTS:ckkseif_core_tests>
)

add_executable(bench_helut
    modules/helut/exp/main_helut.cpp
    $<TARGET_OBJECTS:ckkseif_core>
    $<TARGET_OBJECTS:ckkseif_helut>
    $<TARGET_OBJECTS:ckkseif_core_tests>
    $<TARGET_OBJECTS:ckkseif_helut_tests>
)

add_executable(bench_hecount
    modules/hecount/exp/main_hecount.cpp
    $<TARGET_OBJECTS:ckkseif_core>
    $<TARGET_OBJECTS:ckkseif_hecount>
    $<TARGET_OBJECTS:ckkseif_core_tests>
    $<TARGET_OBJECTS:ckkseif_hecount_tests>
)

add_executable(bench_parity
    modules/parity/exp/main_parity.cpp
    $<TARGET_OBJECTS:ckkseif_core>
    $<TARGET_OBJECTS:ckkseif_parity>
    $<TARGET_OBJECTS:ckkseif_core_tests>
    $<TARGET_OBJECTS:ckkseif_parity_tests>
)
