TAR=wf

obj-m=$(TAR).o
wf-objs=wf_ko.o

KERNELBUILD=/lib/modules/$(shell uname -r)/build/

default:
	make -C $(KERNELBUILD) M=$(CURDIR) modules

install:
	insmod $(TAR).ko

unstall:
	rmmod $(TAR)

pack: clean
	#nothing

clean:
	rm -f *.o *.ko *.mod.c *.order .*.cmd *.symvers
	rm -rf .tmp_versions
