CC := mipsel-linux-gnu-gcc
LD := mipsel-linux-gnu-ld
AS := mipsel-linux-gnu-as
OBJCOPY := mipsel-linux-gnu-objcopy
CFLAGS = -std=gnu99 -nostdlib -mno-abicalls -mabi=eabi -march=r4k -mgp32
ASFLAGS := -mabi=eabi -march=r4k -mgp32
CFLAGS += -O2

CRT_OBJECTS := start.o
C_FILES := $(wildcard *.c)
C_OBJECTS := $(C_FILES:.c=.o)

all: test

test: $(CRT_OBJECTS) $(C_OBJECTS)
	$(LD) -o $@ $(CRT_OBJECTS) $(C_OBJECTS)

%.o: %.s
	$(AS) -o $@ $< $(ASFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f test $(CRT_OBJECTS) $(C_OBJECTS)

.PHONY: all clean

