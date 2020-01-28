add_library(lh_elf exedetails.c loader.c)
set_target_properties(lh_elf PROPERTIES POSITION_INDEPENDENT_CODE ON)