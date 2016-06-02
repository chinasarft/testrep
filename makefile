all:
	gcc -g test.c netspeed.c -lpcap
deb:
	gcc -DDEBUG -g test.c netspeed.c -lpcap -o d.out
