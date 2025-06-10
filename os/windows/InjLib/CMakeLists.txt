add_library(windows_injlib
	GetProcAddress.c GetProcAddress.h
	Inject.c Inject.h
	LenDis.c LenDis.h
	Remote.c Remote.h
	Struct.h
)
install(
	FILES Struct.h
	DESTINATION include/ezinject/os/windows/InjLib
)