cmake_minimum_required(VERSION 3.22.1)

project("poirot" LANGUAGES C ASM)

set(POIROT_CORE_SOURCES
		src/core/detector.c
		src/core/evidence.c
		src/core/hook.c
		src/core/hook.S
		src/core/report.c
		src/core/redirect/redirect.c
		src/core/redirect/probes/fault.c
		src/core/redirect/probes/ghost.c
		src/core/redirect/probes/signal.c
		src/core/shadow/shadow.c
		src/core/shadow/probes/fork.c
		src/core/shadow/probes/parallel.c
		src/core/shadow/probes/protect.c
		src/core/shadow/probes/selfread.c
		src/core/shadow/probes/timing.c
		src/utils/memory.c
		src/utils/signal.c
		src/utils/thread.c
		src/utils/time.c
		src/utils/timeout.c)

add_library(poirot_core OBJECT ${POIROT_CORE_SOURCES})
set_target_properties(poirot_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(poirot_core PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_options(poirot_core PRIVATE
		-Oz
		-Wall
		-Wextra
		-fdata-sections
		-ffunction-sections
		-fvisibility=hidden)

add_library(poirot_static STATIC $<TARGET_OBJECTS:poirot_core>)
set_target_properties(poirot_static PROPERTIES OUTPUT_NAME poirot)
target_include_directories(poirot_static PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}/include)

set(POIROT_SDK_DIR
		${CMAKE_CURRENT_SOURCE_DIR}/../../../build/poirot-sdk/${CMAKE_BUILD_TYPE})
set_target_properties(poirot_static PROPERTIES ARCHIVE_OUTPUT_DIRECTORY
		${POIROT_SDK_DIR}/lib/${ANDROID_ABI})
add_custom_command(TARGET poirot_static POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E make_directory
			${POIROT_SDK_DIR}/include
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			${CMAKE_CURRENT_SOURCE_DIR}/include/poirot.h
			${POIROT_SDK_DIR}/include/poirot.h)

add_library(${CMAKE_PROJECT_NAME} SHARED
		src/main.c
		src/crypto/md5.c
		$<TARGET_OBJECTS:poirot_core>)
add_dependencies(${CMAKE_PROJECT_NAME} poirot_static)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
		-Oz
		-Wall
		-Wextra
		-fdata-sections
		-ffunction-sections
		-fvisibility=hidden)

target_link_options(${CMAKE_PROJECT_NAME} PRIVATE
		-Wl,--gc-sections
		-Wl,--exclude-libs,ALL)
