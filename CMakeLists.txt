cmake_minimum_required(VERSION 3.17)
project(ton-address-miner CUDA)

set(CMAKE_CUDA_STANDARD 14)

set(SUBPROJ ton-address-miner)

set(BIP39_HEADER "${CMAKE_CURRENT_BINARY_DIR}/include/bip39.h")
set(BIP39_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/bip39.cpp")

add_custom_command(
        OUTPUT "${BIP39_HEADER}" "${BIP39_SOURCE}"
        DEPENDS "${PROJECT_SOURCE_DIR}/scripts/prepare_dict.py"
        COMMAND python "${PROJECT_SOURCE_DIR}/scripts/prepare_dict.py" "${PROJECT_SOURCE_DIR}/scripts/bip39.txt" "${BIP39_HEADER}" "${BIP39_SOURCE}"
)

add_custom_target(generate-bip39-dict ALL DEPENDS)

message("${BIP39_HEADER}")

add_executable("${SUBPROJ}" src/main.cu "${BIP39_HEADER}")
target_include_directories("${SUBPROJ}" PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/include")

set_target_properties(
        "${SUBPROJ}"
        PROPERTIES
        CUDA_SEPARABLE_COMPILATION ON)

add_dependencies("${SUBPROJ}" generate-bip39-dict)
