ALLSOURCES=$(wildcard *.c)
ALLHEADERS=$(wildcard *.h)
TARGETSOURCES=target.c
EZPATCHSOURCES=$(filter-out ${TARGETSOURCES},${ALLSOURCES})

ezpatch: ${EZPATCHSOURCES} ${ALLHEADERS}
	gcc $(CFLAGS) -Wall -ggdb ${EZPATCHSOURCES} -o ezpatch
ezpatcharm: ${EZPATCHSOURCES} ${ALLHEADERS}
	arm-lg115x-linux-gnueabi-gcc $(CFLAGS) -std=gnu99 -Wall -ggdb ${EZPATCHSOURCES} -o ezpatcharm

.PHONY: ezpatchup

ezpatchup: ezpatcharm
	ssh root@tv "cat >patcher/ezpatch" < ezpatcharm

ezpatchrun: ezpatch
	./ezpatch $(shell pidof target) return1=x64_xor_rax_rax_ret
ezpatchgdb: ezpatch
	gdb --args ./ezpatch $(shell pidof target) return1=x64_xor_rax_rax_ret
