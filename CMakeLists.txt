cmake_minimum_required(VERSION 3.28)
project(B21)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")
include_directories(include)

include_directories(include)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
endif()

add_compile_options(
        -Os -s -fno-asynchronous-unwind-tables -fno-ident
        -falign-functions=1 -falign-jumps=1 -falign-labels=1
        -fpack-struct=8 -masm=intel -fpermissive
)

add_link_options(
        -Wl,-s,--no-seh
        -Wl,--as-needed,--no-whole-archive
)

add_executable(
        B21
        src/Main.cpp
        src/B21.cpp
        include/B21.h
)

set(ASM_SOURCE_FILES asm/x64/Trampoline.asm)

foreach(ASM_SRC IN LISTS ASM_SOURCE_FILES)
    get_filename_component(ASM_OBJ ${ASM_SRC} NAME_WE)
    set(ASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${ASM_OBJ}.obj)
    add_custom_command(OUTPUT ${ASM_OBJ}
            COMMAND jwasm -win64 -coff -Fo${ASM_OBJ} ${CMAKE_CURRENT_SOURCE_DIR}/${ASM_SRC}
            DEPENDS ${ASM_SRC}
            COMMENT "Assembling ${ASM_SRC}")
    target_sources(B21 PRIVATE ${ASM_OBJ})
endforeach()
