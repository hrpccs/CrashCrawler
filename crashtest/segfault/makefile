CFLAGS = 
CC = $(shell which gcc)
multiThread.bin: multiThread_SegFault.c
	$(CC) $(CFLAGS) -I.  multiThread_SegFault.c -o multiThread.bin
write_read_only_mem.bin: write_read_only_mem.c
	$(CC) $(CFLAGS) -I.  write_read_only_mem.c -o write_read_only_mem.bin
test_multi:
	./multiThread.bin
clean:
	rm *.bin
