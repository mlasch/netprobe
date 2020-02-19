# Makefile for netprobe project

OBJS = main.o handle_packet.o flow.o globals.o
OBJS_TEST = $(filter-out main.o, $(OBJS))

TEST_SRCS = $(wildcard test/*.c)
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_BIN = $(patsubst test/%,bin/test/%,$(TEST_SRCS:.c=))

OUTDIR = bin
OUT = $(OUTDIR)/netprobe

CC = gcc
CFLAGS += -Wall -std=gnu11

LDFLAGS += -lpcap -lpthread -lcurl

ifdef DEBUG
	CFLAGS += -g -O0 -fsanitize=address -fno-omit-frame-pointer -DDEBUG
else
	CFLAGS += -O3
endif

all: build

build:	$(OBJS)
	mkdir -p bin/
	$(CC) $(CFLAGS) $(OBJS) -o $(OUT) $(LDFLAGS)
	
clean:
	rm -rf $(OBJS) $(OUTDIR)

test: $(TEST_BIN)
	@for var in $(TEST_BIN); do \
		echo "Running $$var"; \
		$$var || exit 1; \
	done

bin/test/%: $(OBJS_TEST) $(TEST_OBJS)
	mkdir -p bin/test/
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@
