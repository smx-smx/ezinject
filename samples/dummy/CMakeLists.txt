add_executable(target target.c)
add_ezinject_library(dummy libdummy.c)

add_executable(target_dl target_dl.c)
target_link_libraries(target_dl dl)