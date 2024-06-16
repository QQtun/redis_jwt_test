cmake_minimum_required(VERSION 3.10)

project(MyRedisProject)

set(CMAKE_CXX_STANDARD 17)

# 添加 jwt-cpp 库
find_package(jwt-cpp CONFIG REQUIRED)

# 找到 hiredis 库和头文件
find_path(HIREDIS_INCLUDE_DIR hiredis/hiredis.h)
find_library(HIREDIS_LIBRARY hiredis)

if(NOT HIREDIS_INCLUDE_DIR OR NOT HIREDIS_LIBRARY)
    message(FATAL_ERROR "Could not find hiredis library")
endif()

# 找到 redis-plus-plus 库和头文件
find_path(REDIS_PLUS_PLUS_INCLUDE_DIR sw/redis++/redis++.h)
find_library(REDIS_PLUS_PLUS_LIBRARY redis++)

if(NOT REDIS_PLUS_PLUS_INCLUDE_DIR OR NOT REDIS_PLUS_PLUS_LIBRARY)
    message(FATAL_ERROR "Could not find redis-plus-plus library")
endif()

# 添加主程序
add_executable(my_redis_project main.cpp)

# 链接 hiredis、redis-plus-plus 和 jwt-cpp 库
target_link_libraries(my_redis_project
    PRIVATE
    ${HIREDIS_LIBRARY}
    ${REDIS_PLUS_PLUS_LIBRARY}
    jwt-cpp::jwt-cpp
)

# 包含 jwt-cpp 头文件目录
target_include_directories(my_redis_project PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/external/jwt-cpp/include)
