CC?=gcc
FEATURES=#-DWANT_CLOSED_TRACKER -DWANT_IP_FROM_QUERY_STRING -D_DEBUG_HTTPERROR
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

$(BINARY): $(SOURCES) $(HEADERS)
	$(CC) -o $@ $(SOURCES) $(CFLAGS_production) $(LDFLAGS)
$(BINARY).debug: $(SOURCES) $(HEADERS)
	$(CC) -o $@ $(SOURCES) $(CFLAGS_debug) $(LDFLAGS)
 
clean:
	rm -rf opentracker opentracker.debug *.o *~
