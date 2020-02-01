add_library(lh_sljitmod
	sljitLir.c
)
target_include_directories(lh_sljitmod
	PUBLIC
	${CMAKE_SOURCE_DIR}/include/sljit
)
target_link_libraries(lh_sljitmod pthread)
set_target_properties(lh_sljitmod PROPERTIES POSITION_INDEPENDENT_CODE ON)