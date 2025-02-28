cmake_minimum_required(VERSION 3.22)

add_compile_definitions(PYDA_VERSION="${CMAKE_PROJECT_VERSION}")

if (APPLE)
  add_library(tool SHARED tool.c pyda_core_py.c pyda_core.c pyda_threads.c pyda_unwind.c pyda_patch_python.c pyda_compiler.c macos/pyda_threads_macos.c macos/macho.c)
else()
  add_library(tool SHARED tool.c pyda_core_py.c pyda_core.c pyda_threads.c pyda_unwind.c pyda_patch_python.c pyda_compiler.c linux/pyda_threads_linux.c)
endif()

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

find_package(Python3 3.10 EXACT COMPONENTS Development)
if (NOT Python3_FOUND)
  message(FATAL_ERROR "Python required to build")
endif(NOT Python3_FOUND)

if (APPLE)
  target_link_libraries(tool ${Python3_LIBRARIES})
  target_include_directories(tool PRIVATE ${Python3_INCLUDE_DIRS} include/)
else()
  target_link_libraries(tool ${Python3_LIBRARIES} unwind)
  target_include_directories(tool PRIVATE ${LIBUNWIND_INCLUDE_DIRS} ${Python3_INCLUDE_DIRS} include/)
  target_link_directories(tool PRIVATE ${LIBUNWIND_LIBRARY_DIRS})
endif()

target_compile_options(tool PUBLIC -DPYDA_DYNAMORIO_CLIENT -Werror)

configure_DynamoRIO_client(tool)
use_DynamoRIO_extension(tool drmgr)
use_DynamoRIO_extension(tool drcontainers)
use_DynamoRIO_extension(tool drreg)
#use_DynamoRIO_extension(tool drtools)

# the standalone python shared library (no dynamorio linked here)
# add_library(pyda_core SHARED pyda_core_py.c pyda_core.c)
# set_target_properties(pyda_core PROPERTIES PREFIX "")
# target_include_directories(pyda_core PRIVATE ${Python3_INCLUDE_DIRS})
# target_link_libraries(pyda_core ${Python3_LIBRARIES} unwind)
