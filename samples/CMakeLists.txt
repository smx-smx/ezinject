add_subdirectory(dummy)

if(EZ_SAMPLE_PYTHON)
	add_subdirectory(pyloader)
endif()

if(EZ_SAMPLE_DOTNET)
	add_subdirectory(dotnetcore)
endif()

if(EZ_SAMPLE_MONO)
	add_subdirectory(mono)
endif()
