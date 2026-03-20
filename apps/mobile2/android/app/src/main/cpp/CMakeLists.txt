cmake_minimum_required(VERSION 3.22.1)
project(amoon_integrity)

add_library(amoon_integrity SHARED integrity.cpp)

# Strip debug symbols in release, harden binary
target_compile_options(amoon_integrity PRIVATE
    -O2
    -fvisibility=hidden
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

target_link_libraries(amoon_integrity
    android
    log
)
