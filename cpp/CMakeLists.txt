cmake_minimum_required(VERSION 3.16)
project(dynamic_cssc_openfhe_probes LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenFHE CONFIG REQUIRED)

message(STATUS "OpenFHE version: ${BASE_OPENFHE_VERSION}")
message(STATUS "OpenFHE include: ${OpenFHE_INCLUDE}")
message(STATUS "OpenFHE libraries: ${OpenFHE_LIBDIR}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS}")
include_directories(SYSTEM
  ${OPENMP_INCLUDES}
  ${OpenFHE_INCLUDE}
  ${OpenFHE_INCLUDE}/third-party/include
  ${OpenFHE_INCLUDE}/core
  ${OpenFHE_INCLUDE}/pke
  ${OpenFHE_INCLUDE}/binfhe
)

if(UNIX AND NOT APPLE)
  add_link_options(-Wl,--no-as-needed)
endif()

link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})
link_libraries(${OpenFHE_SHARED_LIBRARIES})

add_executable(rotation_probe rotation_probe.cpp)
add_executable(openfhe_microbench microbench.cpp)

target_compile_options(rotation_probe PRIVATE -Wall -Wextra -Wpedantic)
target_compile_options(openfhe_microbench PRIVATE -Wall -Wextra -Wpedantic)
