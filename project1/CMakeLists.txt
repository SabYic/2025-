cmake_minimum_required(VERSION 3.16)
project(sm4_example C)

# 要求 C11，打开比较严格的警告（按需调整）
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-std=c11 -Wall -Wextra -Wpedantic)  # 开发时建议加上 -Werror 变成更严格：-Werror

# 定义一个静态库 libsm4.a（也可以改成 SHARED）
add_library(sm4 STATIC sm4.c)
add_library(sm4ttable STATIC sm4_withTtable.c)

# 让使用者能找到 sm4.h
target_include_directories(sm4 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# 生成最终的可执行程序
add_executable(sm4_demo main.c)

# 链接 sm4 库到 main
target_link_libraries(sm4_demo PRIVATE sm4 sm4ttable)
