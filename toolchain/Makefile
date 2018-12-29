CC := mipsel-linux-gnu-gcc
LD := mipsel-linux-gnu-ld
AS := mipsel-linux-gnu-as
OBJCOPY := mipsel-linux-gnu-objcopy
CFLAGS = -std=gnu99 -nostdlib -mno-abicalls -mabi=eabi -march=vr4300 -mgp32
ASFLAGS := -mabi=eabi -march=vr4300 -mgp32
CFLAGS += -O2

AS_FILES := $(wildcard *.s)
AS_OBJECTS := $(AS_FILES:.s=.o)
C_FILES := $(wildcard *.c)
C_OBJECTS := $(C_FILES:.c=.o)

all: test

test: $(AS_OBJECTS) $(C_OBJECTS)
	$(LD) -o $@ $(AS_OBJECTS) $(C_OBJECTS)

%.o: %.s
	$(AS) -o $@ $< $(ASFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f test $(AS_OBJECTS) $(C_OBJECTS)

.PHONY: all clean

