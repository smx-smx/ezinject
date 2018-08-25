ALLSOURCES=$(wildcard *.c)
TARGETSOURCES=target.c
EZPATCHSOURCES=$(filter-out ${TARGETSOURCES},${ALLSOURCES})

ezpatch: ${EZPATCHSOURCES}
	gcc -Wall -ggdb ${EZPATCHSOURCES} -o ezpatch
ezpatcharm: ${EZPATCHSOURCES}
	arm-lg115x-linux-gnueabi-gcc -std=gnu99 -Wall -ggdb ${EZPATCHSOURCES} -o ezpatcharm

.PHONY: ezpatchup

ezpatchup: ezpatcharm
	ssh root@tv "cat >patcher/ezpatch" < ezpatcharm

ezpatchrun: ezpatch
	./ezpatch $(shell pidof target) return1=x64_xor_rax_rax_ret
ezpatchgdb: ezpatch
	gdb --args ./ezpatch $(shell pidof target) return1=x64_xor_rax_rax_ret
