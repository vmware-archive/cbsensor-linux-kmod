project(cbevent-event-parser)
set(CMAKE_CXX_STANDARD 14)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

add_executable(${PROJECT_NAME}
        parser.cpp
        CB_EVENT_JSON.cpp
        CB_CMDLINE.h
        CB_DRIVER_REQUEST.h
        CB_EVENT_BLOCK_RESPONSE.h
        CB_EVENT_DNS_RESPONSE.h
        CB_EVENT_DYNAMIC.h
        CB_EVENT_FILE_GENERIC.h
        CB_EVENT_FILTER.h
        CB_EVENT.h
        CB_EVENT_HEARTBEAT.h
        CB_EVENT_MODULE_LOAD.h
        CB_EVENT_NETWORK_CONNECT.h
        CB_EVENT_PROCESS_EXIT.h
        CB_EVENT_PROCESS_INFO.h
        CB_EVENT_PROCESS_START.h
        CB_EVENT_TYPE.h
        CB_FILE_TYPE.h
        CB_ISOLATION_MODE.h
        CB_PROTECTION_CONTROL.h
        CB_SOCK_ADDR.h
        CB_TRUSTED_PATH.h
        )

target_include_directories(${PROJECT_NAME} INTERFACE
        ${CONAN_INCLUDE_DIRS}
        ${PROJECT_SOURCE_DIR}
        )

add_library(cbevent_json
        CB_EVENT_JSON.cpp
        )
