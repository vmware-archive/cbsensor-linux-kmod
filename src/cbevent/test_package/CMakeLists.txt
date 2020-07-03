cmake_minimum_required(VERSION 3.14)
project(cbevent-test CXX)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

add_executable(${PROJECT_NAME} cbevent_test.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE ${CONAN_INCLUDE_DIRS})

# CTest is a testing tool that can be used to test your project.
enable_testing()
add_test(NAME ${PROJECT_NAME}
         WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
         COMMAND ${PROJECT_NAME})
