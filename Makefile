obj-m += lsm_stacker.o
lsm_stacker-objs := stacker.o probe.o

KERNEL=$(shell uname -r)
BUILD=/lib/modules/${KERNEL}/build
all:modules

modules: 
	$(MAKE) -C ${BUILD} M=$(PWD) modules

clean:
	@-rm *.ko *.o *.mod.c  Module.* .tmp_versions -rf
