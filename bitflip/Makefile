obj-m += bitflip.o

PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean: test-clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test-program: test.c
	gcc $< -o test-program

test: test-program
	./$<

test-clean:
	$(RM) test-program

.PHONY: all clean test test-clean