OBJECTS = main.o
TARGET = evil.sys
CFLAGS = -I /usr/x86_64-w64-mingw32/include/ddk -I /usr/x86_64-w64-mingw32/include -DMINGW -std=c23 -Wall -m64 -shared

all: $(TARGET)
clean:
	rm -f $(OBJECTS) $(TARGET) driver_bytes.h
%.o: %.c
	x86_64-w64-mingw32-gcc $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	x86_64-w64-mingw32-gcc $(CFLAGS) -Wl,--subsystem,native -Wl,--image-base,0x10000 \
	-Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 \
	-Wl,--entry,DriverEntry@8 -Wl,--stack,0x40000 -Wl,--dynamicbase -Wl,--nxcompat \
	-nostartfiles -nostdlib -o $(TARGET) \
	$(OBJECTS) -lntoskrnl -lhal
	xxd -i evil.sys >> driver_bytes.h
