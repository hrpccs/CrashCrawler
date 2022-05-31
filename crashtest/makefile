CFLAGS = -O3 -fopenmp
CC = $(shell which gcc)
multiThread.bin: multiThread_SegFault.c
	$(CC) $(CFLAGS) -I.  multiThread_SegFault.c -o multiThread.bin
test_multi:
	./multiThread.bin
clean:
	rm *.bin
