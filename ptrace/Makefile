all : wrapper

CFLAGS += -g -Wall

LDFLAGS += -lrt

wrapper : wrapper.o util.o

wrapper.o : wrapper.c syscall_names.h util.h

util.o : util.c util.h

clean :
	-$(RM) *.o *~ wrapper


