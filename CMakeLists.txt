cmake_minimum_required(VERSION 3.17)
project(ton-address-miner CUDA)

set(CMAKE_CUDA_STANDARD 14)

set(SUBPROJ ton-address-miner)

set(BIP39_HEADER "${CMAKE_CURRENT_BINARY_DIR}/include/bip39.cuh")
set(BIP39_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/bip39.cu")

add_custom_command(
        OUTPUT "${BIP39_HEADER}" "${BIP39_SOURCE}"
        DEPENDS "${PROJECT_SOURCE_DIR}/scripts/prepare_dict.py"
        COMMAND python "${PROJECT_SOURCE_DIR}/scripts/prepare_dict.py" "${PROJECT_SOURCE_DIR}/scripts/bip39.txt" "${BIP39_HEADER}" "${BIP39_SOURCE}"
)

add_custom_target(generate-bip39-dict ALL DEPENDS)

message("${BIP39_HEADER}")

add_executable("${SUBPROJ}"
        src/main.cu
        src/hmac_sha512.cu
        src/hmac_sha512.cuh
        src/pbkdf2.cu
        src/pbkdf2.cuh
        src/sha256.cu
        src/sha256.cuh
        src/sha512.cu
        src/sha512.cuh
        "${BIP39_SOURCE}"
        "${BIP39_HEADER}")
target_include_directories("${SUBPROJ}" PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/include")
target_link_libraries("${SUBPROJ}" PRIVATE curand)

set_target_properties(
        "${SUBPROJ}"
        PROPERTIES
        CUDA_SEPARABLE_COMPILATION ON)

add_dependencies("${SUBPROJ}" generate-bip39-dict)
