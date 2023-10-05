cmake_minimum_required(VERSION 3.10)

project(coredump)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_COMPILER "clang")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_COMPILER "clang++")
add_compile_options(-g -O2 -static)

add_executable(coredump latencycatch.c)

include_directories(
    ${CMAKE_SOURCE_DIR}/crashcrawler/include 
    ${CMAKE_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/include 
    ${CMAKE_BINARY_DIR}/src/libbpf/include/uapi 
    /usr/include )

add_dependencies(coredump coredump_bpf)


add_library(coredump_bpf OBJECT ${CMAKE_SOURCE_DIR}/coredump/latencycatch.bpf.c)
target_compile_options(coredump_bpf  PRIVATE -target bpf -D__TARGET_ARCH_x86)
set_target_properties(coredump_bpf PROPERTIES COMPILE_FLAGS "-xc")
add_dependencies(coredump_bpf coredump_bpf_program)

add_custom_target(coredump_bpf_program DEPENDS ${CMAKE_SOURCE_DIR}/coredump/latencycatch.bpf.c)

add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/coredump/latencycatch.skel.h
    COMMAND cp $<TARGET_OBJECTS:coredump_bpf> /tmp/latencycatch.bpf.o
    COMMAND bpftool gen skeleton /tmp/latencycatch.bpf.o > ${CMAKE_SOURCE_DIR}/coredump/latencycatch.skel.h
    COMMAND rm /tmp/latencycatch.bpf.o
    DEPENDS coredump_bpf coredump_bpf_program
)

target_link_libraries(
    coredump 
    ${CMAKE_BINARY_DIR}/lib64/libbpf.a 
    elf 
    z 
    )