cmake_minimum_required(VERSION 3.19)
project(mineaddr C)

set(CMAKE_C_STANDARD 11)

add_executable(mineaddr
        src/main.c
        src/bip39.h
        src/bip39.c
        src/cell.h
        src/cell.c
        src/mnemonic.h
        src/mnemonic.c
        src/contract.h
        src/contract.c)

target_link_libraries(mineaddr crypto pthread)
target_compile_options(mineaddr PUBLIC -O3 -m64 -march=native -Wall -Wextra)
