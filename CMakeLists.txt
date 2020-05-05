cmake_minimum_required (VERSION 3.4)

# 项目信息
project (Groudhog VERSION 1.0)

set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

include_directories(C:\\mingw64\\opt\\include)
link_directories(C:\\mingw64\\opt\\lib)

# 指定生成目标
add_executable(LibcryptoTest test.cpp)
target_link_libraries(LibcryptoTest libcrypto.a)

add_executable(local local.cpp sock5.cpp)
target_link_libraries(local libwsock32.a)

add_executable(remote remote.cpp sock5.cpp)
target_link_libraries(remote libwsock32.a)

