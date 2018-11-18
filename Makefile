CC       = gcc
CFLAGS   = -g -O -MMD -MP -Wall
#CFLAGS  += -D_DEBUG
CPPFLAGS =
LDFLAGS  =
LIBS     =
SRCS     = wow.c
OBJS     = $(SRCS:%.c=%.o)
DEPS     = $(SRCS:%.c=%.d)
BIN      = wow

.SUFFIXES: .c.o

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) $^ -o $@

ALL: $(BIN)

-include $(DEPS)

clean:
	rm -f $(BIN) $(OBJS) $(DEPS) *~
