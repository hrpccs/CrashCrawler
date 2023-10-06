BIN  = 1_parse_elf
OBJS = 1_parse_elf.o
CC   = gcc
INCLUDE := -I /home/tz/huawei/dumptest/build/include
LIBS    := /home/tz/huawei/dumptest/build/lib/libelf.a
$(BIN):$(OBJS)
	$(CC) -g  $^ -o $@	$(LIBS)
%.o:%.c
	$(CC) -g -c $< -o $@ $(INCLUDE)
PHONY:clean
clean:
	rm -f $(OBJS) $(BIN)