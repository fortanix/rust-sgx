obj-m += sgxmod.o
sgxmod-objs := dev.o encls.o

all: mod clear user_multi user

mod:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

modclean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

clear:
	g++ -std=gnu++11 clear.cpp -o clear

user_multi:
	g++ -std=gnu++11 user_multi.cpp -o user_multi

user:
	gcc user.c -o user

clean: modclean
	rm -f user user_multi clear
