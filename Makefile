ALLHEADERS=$(wildcard *.h)
COMMONSOURCES=util.c elfparse.c
TARGETSOURCES=target.c
EZPATCHSOURCES:=${COMMONSOURCES} ezpatch.c

OBJS=ezpatch ezpatcharm target

CFLAGS += -std=gnu99 -Wall -ggdb
ifdef DEBUG
CFLAGS += -DDEBUG
endif

ezpatch: ${EZPATCHSOURCES} ${ALLHEADERS}
	gcc $(CFLAGS) ${EZPATCHSOURCES} -o ezpatch
ezpatcharm: ${EZPATCHSOURCES} ${ALLHEADERS}
	arm-lg115x-linux-gnueabi-gcc $(CFLAGS) ${EZPATCHSOURCES} -o ezpatcharm

.PHONY: ezpatchup ezpatchrun ezpatchgdb clean

ezpatchup: ezpatcharm
	ssh root@tv "cat >patcher/ezpatch" < ezpatcharm

ezpatchrun: ezpatch
	./ezpatch $(shell pidof target) return1=x64_xor_rax_rax_ret
ezpatchgdb: ezpatch
	gdb --args ./ezpatch $(shell pidof target) return1=x64_xor_rax_rax_ret

clean:
	rm -f ${OBJS}
