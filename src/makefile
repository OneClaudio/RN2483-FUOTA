CC=      gcc
LIBS=   -pthread
CFLAGS= -std=gnu99 -g -Wall -D_GNU_SOURCE -Wextra
# -pedantic
DBGFLAG=-DDEBUG

WDIR= .
HEADERS= ./config.h ./log.h ./lora.h ./rn2483.h ./serial.h ./tiny-aes.h
OBJECTS= ./log.o ./lora.o ./rn2483.o ./tiny-aes.o ./state.o ./fuota.o


./%.o: ./%.c    $(HEADERS)
	$(CC) $(CFLAGS) -I. $< -c -o $@

test: $(OBJECTS)
	$(CC) $(CFLAGS) -I. $+ -o $@

clean:
	rm -f ./*.o
