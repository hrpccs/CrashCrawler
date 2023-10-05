cmake_minimum_required(VERSION 3.10)

project(crashcrawler)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_COMPILER "clang")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_COMPILER "clang++")
add_compile_options(-g -O2 -static)

include_directories(${CMAKE_BINARY_DIR})
file(GLOB_RECURSE CPP_SOURCES "*.cpp")
add_executable(crashcrawler ${CPP_SOURCES})

include_directories(
    ${CMAKE_SOURCE_DIR}/crashcrawler/include 
    ${CMAKE_BINARY_DIR}/include 
    ${CMAKE_BINARY_DIR}/src/libbpf/include/uapi 
    /usr/include )

add_dependencies(crashcrawler crashcrawler_skel)

# Create a library from crashcrawler.bpf.c
add_library(crashcrawler_bpf OBJECT ${CMAKE_SOURCE_DIR}/crashcrawler/crashcrawler.bpf.c)
target_compile_options(crashcrawler_bpf PRIVATE -target bpf -D__TARGET_ARCH_x86)
set_target_properties(crashcrawler_bpf PROPERTIES COMPILE_FLAGS "-xc")
add_dependencies(crashcrawler_bpf libbpf vmlinux.h crashcrawler_bpf_program)

add_custom_target(crashcrawler_bpf_program DEPENDS ${CMAKE_SOURCE_DIR}/crashcrawler/crashcrawler.bpf.c)

# Generate crashcrawler.skel.h from crashcrawler.bpf.o
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/crashcrawler/include/crashcrawler.skel.h
    COMMAND cp $<TARGET_OBJECTS:crashcrawler_bpf> /tmp/crashcrawler.bpf.o
    COMMAND bpftool gen skeleton /tmp/crashcrawler.bpf.o > ${CMAKE_SOURCE_DIR}/crashcrawler/include/crashcrawler.skel.h
    COMMAND rm /tmp/crashcrawler.bpf.o
    DEPENDS crashcrawler_bpf crashcrawler_bpf_program
)

target_link_libraries(
    crashcrawler 
    ${CMAKE_BINARY_DIR}/lib64/libbpf.a 
    elf 
    z 
    pthread 
    )

add_custom_target(crashcrawler_skel DEPENDS ${CMAKE_SOURCE_DIR}/crashcrawler/include/crashcrawler.skel.h)

# Download and build libbpf
include(ExternalProject)
set(LIBBPF_ROOT ${CMAKE_BINARY_DIR}/src/libbpf)
set(LIBBPF_LIB_DIR ${LIBBPF_ROOT}/lib)
set(LIBBPF_INCLUDE_DIR ${LIBBPF_ROOT}/include)

set(LIBBPF_MAKE cd ${LIBBPF_ROOT}/src && make -j8 BUILD_STATIC_ONLY=1)
set(LIBBPF_INSTALL cd ${LIBBPF_ROOT}/src && make PREFIX=${CMAKE_BINARY_DIR} install)
ExternalProject_Add(libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
    GIT_TAG v1.2.0
    PREFIX ${CMAKE_BINARY_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${LIBBPF_MAKE}
    INSTALL_COMMAND ${LIBBPF_INSTALL}
)
add_dependencies(crashcrawler libbpf)

include(ExternalProject)

add_custom_target(vmlinux.h DEPENDS ${CMAKE_SOURCE_DIR}/crashcrawler/include/vmlinux.h)
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/crashcrawler/include/vmlinux.h
    COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_SOURCE_DIR}/crashcrawler/include/vmlinux.h
)

# set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
