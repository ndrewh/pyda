cmake_minimum_required(VERSION 3.22)

add_compile_definitions(PYDA_VERSION="${CMAKE_PROJECT_VERSION}")

add_library(tool SHARED tool.c pyda_core_py.c pyda_core.c pyda_threads.c pyda_patch_python.c)
find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

find_package(Python3 3.10 EXACT COMPONENTS Interpreter Development)
if (NOT Python3_FOUND)
  message(FATAL_ERROR "Python required to build")
endif(NOT Python3_FOUND)

target_include_directories(tool PRIVATE ${Python3_INCLUDE_DIRS})
target_link_libraries(tool ${Python3_LIBRARIES})
target_compile_options(tool PUBLIC -DPYDA_DYNAMORIO_CLIENT)

configure_DynamoRIO_client(tool)
use_DynamoRIO_extension(tool drmgr)
#use_DynamoRIO_extension(tool drtools)

# the standalone python shared library (no dynamorio linked here)
add_library(pyda_core SHARED pyda_core_py.c pyda_core.c)
set_target_properties(pyda_core PROPERTIES PREFIX "")
target_include_directories(pyda_core PRIVATE ${Python3_INCLUDE_DIRS})
target_link_libraries(pyda_core ${Python3_LIBRARIES})