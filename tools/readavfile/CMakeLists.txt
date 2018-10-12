cmake_minimum_required (VERSION 2.8)

project(testreader)

add_definitions("-Wall -g")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/")
link_directories("${CMAKE_CURRENT_SOURCE_DIR}/lib")

add_library(simreader STATIC
	adts.c
	avreader.c
	kmp.c
	adts.h
	avreader.h
	kmp.h
)

add_executable(testreader
	flag.h
	flag.c
	main.c
)


target_link_libraries(testreader simreader)
