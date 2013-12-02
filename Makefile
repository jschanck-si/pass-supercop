CC=gcc

CFLAGS += -c
CFLAGS += -Wall
CFLAGS += -O3 -ffast-math -mtune=native

LDFLAGS = -lm

SOURCES=bsparseconv.c\
		crypto_hash_sha512.c\
		formatc.c\
		poly.c\
		hash.c\
		ntt.c\
		sign.c\
		crypto_stream.c\
		randombytes.c\
		fastrandombytes.c\
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



