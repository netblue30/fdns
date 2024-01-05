all: dnsc

include ../common.mk

%.o : %.c $(H_FILE_LIST)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(INCLUDE) -c $< -o $@

dnsc: $(OBJS)
	$(CC)  $(LDFLAGS) -o $@ $(OBJS)  $(LIBS) $(EXTRA_LDFLAGS)

clean:; rm -f *.o dnsc *.gcov *.gcda *.gcno

distclean: clean
