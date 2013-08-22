CC=gcc

CFLAGS += -c
CFLAGS += -Wall -Wno-unused-variable
CFLAGS += -O2 -ffast-math -m64
CFLAGS += -DUSE_FFTW=1
CFLAGS += -DVERIFY=1
CFLAGS += -DDEBUG=0

LDFLAGS= -lfftw3l

SOURCES=bsparseconv.c\
		crypto_hash_sha512.c\
		formatc.c\
		poly.c\
		hash.c\
		ntt.c\
		key.c\
		sign.c\
		verify.c\
		bench.c

OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=bench

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)



