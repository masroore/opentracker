CC?=gcc
FEATURES=#-DWANT_IP_FROM_QUERY_STRING -D_DEBUG_HTTPERROR
OPTS_debug=-g -ggdb #-pg # -fprofile-arcs -ftest-coverage
OPTS_production=-s -Os
CFLAGS+=-I../libowfat -Wall -pipe -Wextra #-pedantic #-ansi
LDFLAGS+=-L../libowfat/ -lowfat
 
BINARY = opentracker
HEADERS=trackerlogic.h scan_urlencoded_query.h
SOURCES=opentracker.c trackerlogic.c scan_urlencoded_query.c
 
all: $(BINARY) $(BINARY).debug

CFLAGS_production = $(CFLAGS) $(OPTS_production) $(FEATURES)
CFLAGS_debug = $(CFLAGS) $(OPTS_debug) $(FEATURES)

OBJECTS_debug = $(SOURCES:%.c=%.debug.o)
OBJECTS_production = $(SOURCES:%.c=%.production.o)

$(OBJECTS_debug) $(OBJECTS_production): $(HEADERS)

%.production.o : CFLAGS := $(CFLAGS_production)
%.debug.o : CFLAGS := $(CFLAGS_debug)

%.production.o : %.c 
	$(COMPILE.c) $(OUTPUT_OPTION) $<
%.debug.o : %.c 
	$(COMPILE.c) $(OUTPUT_OPTION) $<

$(BINARY): $(OBJECTS_production)
	$(CC) $^ -o $@ $(CFLAGS_production) $(LDFLAGS)
$(BINARY).debug: $(OBJECTS_debug)
	$(CC) $^ -o $@ $(CFLAGS_debug) $(LDFLAGS)
 
 clean:
	rm -rf opentracker *.o *~
 
