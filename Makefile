CC=gcc

CFLAGS += -c
CFLAGS += -Wall
CFLAGS += -O3 -ffast-math -mtune=native -malign-double

LDFLAGS = -lfftw3 -lm


SOURCES=bsparseconv.c\
		crypto_hash_sha512.c\
		formatc.c\
		poly.c\
		hash.c\
		ntt.c\
		key.c\
		sign.c\
		verify.c\
		crypto_stream.c\
		randombytes.c\
		fastrandombytes.c\
		bench.c

OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=bench

PARAMSETS=433 577 769 1153

all: wisdom data $(SOURCES) $(EXECUTABLE)

vpath %.dat data
wisdom: $(addsuffix _wisdom.dat, $(PARAMSETS))
%_wisdom.dat :
	./wiseup.sh $*

data: $(addsuffix _rader.dat, $(PARAMSETS))
data: $(addsuffix _perm.dat, $(PARAMSETS))
data: $(addsuffix _points.dat, $(PARAMSETS))
%_rader.dat %_points.dat %_perm.dat:
	$(warning Runtime data for set $* not present ($@). See README.)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)



