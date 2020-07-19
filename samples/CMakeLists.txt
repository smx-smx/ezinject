add_subdirectory(dummy)
add_subdirectory(pyloader)

if(EZ_SAMPLE_DOTNET)
	add_subdirectory(dotnetcore)
endif()

if(EZ_SAMPLE_MONO)
	add_subdirectory(mono)
endif()
