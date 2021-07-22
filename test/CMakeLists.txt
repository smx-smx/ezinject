add_executable(test_basic_injection basic_injection.cpp)
target_link_libraries(test_basic_injection pthread)
add_dependencies(test_basic_injection ezinject target dummy)

add_test(
	NAME basic_injection 
	COMMAND test_basic_injection
		$<TARGET_FILE:target>
		$<TARGET_FILE:ezinject>
		$<TARGET_FILE:dummy>
)