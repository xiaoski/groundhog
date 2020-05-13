cmake_minimum_required (VERSION 3.4)

# 项目信息
project (Groudhog VERSION 1.0)

SET (OPENSSL_ROOT_DIR E:\\MinGW\\mingw32\\opt)
SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
message(${OPENSSL_CRYPTO_LIBRARY})
message(${OPENSSL_INCLUDE_DIR})

SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

include_directories(${OPENSSL_INCLUDE_DIR})
# link_directories(C:\\mingw64\\opt\\lib)

# 指定生成目标
add_executable(LibcryptoTest test.cpp)
target_link_libraries(LibcryptoTest ${OPENSSL_CRYPTO_LIBRARY})

add_executable(local local.cpp sock5.cpp)
target_link_libraries(local ${OPENSSL_CRYPTO_LIBRARY} libwsock32.a)

add_executable(remote remote.cpp sock5.cpp)
target_link_libraries(remote ${OPENSSL_CRYPTO_LIBRARY} libwsock32.a)

