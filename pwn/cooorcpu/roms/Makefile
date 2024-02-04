PREFIX = riscv32-unknown-elf

CC = $(PREFIX)-gcc
LD = $(PREFIX)-ld
STRIP = $(PREFIX)-strip
OBJCOPY = $(PREFIX)-objcopy
CFLAGS = -march=rv32g -ffreestanding -nostdlib -c -O0
LDFLAGS = -melf32lriscv

all: system_rom.rom user_rom.rom

.PHONY: all clean
.PRECIOUS: %.bin %.o

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

%.bin: %.o %.ld
	$(LD) $< -T $(word 2,$^) $(LDFLAGS) -o $@

%.raw: %.bin
	$(STRIP) $<
	$(OBJCOPY) -O binary $< $@

%.rom: %.raw
	cat $< | od -An -vtx1 -w1 | cut -c2- > $@

clean:
	rm -f *.o *.bin *.raw *.rom
