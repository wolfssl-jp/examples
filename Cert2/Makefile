PROG := wolfssl_sample_server
SRCS := sample_server.c
CFLAGS  := -g -Wall -MMD -MP
LDFLAGS := -lwolfssl
OBJS := $(SRCS:%.c=%.o)
DEPS := $(SRCS:%.c=%.d)

CC := gcc

all: $(PROG)

-include $(DEPS)

$(PROG): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) 

%.o: %.c
	$(CC) -c $(CFLAGS) $<

clean:
	rm -f $(PROG) $(OBJS) $(DEPS)
