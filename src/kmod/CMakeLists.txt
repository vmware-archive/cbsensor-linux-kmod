cmake_minimum_required(VERSION 3.14)

project(cbsensor VERSION 1.0.3 LANGUAGES C)

if(EXISTS ${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    conan_basic_setup()
    if(CONAN_KERNEL-DEVEL_ROOT)
        set(KERNELDIR ${CONAN_KERNEL-DEVEL_ROOT}/kernel)
    endif()
endif()

if(NOT DEFINED KERNELDIR)
    execute_process(COMMAND uname -r OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE KERNEL_VERSION)
    set(KERNELDIR /lib/modules/${KERNEL_VERSION}/build)
endif()

string(TIMESTAMP TODAY "%Y-%m-%d %H:%M:%SZ")

configure_file(version.h.in ${CMAKE_CURRENT_SOURCE_DIR}/version.h)

# Find kernel headers
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(DRIVER_FILE cbsensor.ko)

set(KBUILD_CMD $(MAKE) --no-print-directory -C ${KERNELDIR} M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} o=${CMAKE_CURRENT_BINARY_DIR} V=2)

set(SYMBOLS_INSTALL_COMMAND objcopy --only-keep-debug ${DRIVER_FILE} ${DRIVER_FILE}.debug && ${CMAKE_STRIP} --strip-unneeded ${DRIVER_FILE})

if (CMAKE_BUILD_TYPE STREQUAL Debug)
    set(KMOD_FLAGS "-g -Wall -Wformat")
else()
    set(KMOD_FLAGS "-Wall -Wformat")
endif()

# Generate the Kbuild file through cmake.
FILE(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "obj-m := cbsensor.o
ccflags-y := ${KMOD_FLAGS}

cbsensor-objs := drvmain.o \
                 file-helper.o \
                 file-hooks.o \
                 logger.o \
                 lsm.o \
                 modules.o \
                 lsmutils.o \
                 net-helper.o \
                 net-hooks.o \
                 process-hooks.o \
                 task-helper.o \
                 fops-comm.o \
                 process-tracking.o \
                 cb-isolation.o \
                 cb-banning.o \
                 netfilter.o \
                 hash-table-generic.o \
                 file-write-tracking.o \
                 syscall_init.o \
                 syscall_stubs.o \
                 file-types.o \
                 cb-procfs.o \
                 module-hooks.o \
                 test-logging.o \
                 ktfutce.o \
                 file-write-cache.o \

CC=${CMAKE_C_COMPILER}")

add_custom_command(OUTPUT ${DRIVER_FILE}
        COMMAND ${KBUILD_CMD} modules
        DEPENDS
            cb-banning.c
            cb-isolation.c
            cb-procfs.c
            drvmain.c
            file-helper.c
            file-hooks.c
            file-write-cache.c
            file-write-tracking.c
            file-types.c
            fops-comm.c
            hash-table-generic.c
            logger.c
            lsm.c
            lsmutils.c
            module-hooks.c
            modules.c
            netfilter.c
            net-helper.c
            net-hooks.c
            process-hooks.c
            process-tracking.c
            syscall_init.c
            syscall_stub.h
            syscall_stubs.S
            task-helper.c
            test-logging.c
            ktfutce.c
        VERBATIM)

add_custom_target(cbsensor ALL DEPENDS ${DRIVER_FILE})
