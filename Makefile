CC=gcc

CFLAGS += -c -Wall -O2 -ffast-math
CFLAGS += -DUSE_FFTW=1
CFLAGS += -DVERIFY=0
CFLAGS += -DDEBUG=0

LDFLAGS= -lfftw3l
SOURCES=circonv.c crypto_hash_sha512.c formatc.c ntt.c sign.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=test

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)



