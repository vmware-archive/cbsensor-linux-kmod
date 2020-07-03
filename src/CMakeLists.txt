# This CMake file is not used for building the kernel module.
# It is only present to allow CMake aware IDEs (like CLion) to navigate,
# autocomplete, static analyze, and apply automated refactorings to the code.

cmake_minimum_required(VERSION 3.6)
project(cbr-linux-kernel)

add_subdirectory(cbevent)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

add_library(cbsensor-kmod
        kmod/cb-banning.c
        kmod/cb-banning.h
        kmod/cb-isolation.c
        kmod/cb-isolation.h
        kmod/cb-procfs.c
        kmod/cb-test.h
        kmod/dbg.h
        kmod/drvmain.c
        kmod/file-helper.c
        kmod/file-hooks.c
        kmod/file-process-tracking.c
        kmod/file-process-tracking.h
        kmod/file-types.c
        kmod/file-types.h
        kmod/fops-comm.c
        kmod/hash-table-generic.c
        kmod/hash-table-generic.h
        kmod/InodeState.h
        kmod/logger.c
        kmod/lsm.c
        kmod/lsmutils.c
        kmod/module-hooks.c
        kmod/modules.c
        kmod/netfilter.c
        kmod/net-helper.c
        kmod/net-hooks.c
        kmod/network-tracking.h
        kmod/priv.h
        kmod/process-hooks.c
        kmod/process-tracking.c
        kmod/process-tracking.h
        kmod/syscall_init.c
        kmod/syscall_stub.h
        kmod/task-helper.c
        kmod/test-logging.c
        kmod/version.h
        )
target_include_directories(cbsensor-kmod PUBLIC ${CONAN_INCLUDE_DIRS})
