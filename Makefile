CC?=gcc
FEATURES=#-DWANT_TRACKER_SYNC -DWANT_BLACKLISTING -DWANT_CLOSED_TRACKER -DWANT_UTORRENT1600_WORKAROUND #-DWANT_IP_FROM_QUERY_STRING -D_DEBUG_HTTPERROR
OPTS_debug=-g -ggdb #-pg # -fprofile-arcs -ftest-coverage
OPTS_production=-Os
CFLAGS+=-I../libowfat -Wall -pipe -Wextra #-pedantic -ansi
LDFLAGS+=-L../libowfat/ -lowfat
 
BINARY =opentracker
HEADERS=trackerlogic.h scan_urlencoded_query.h ot_mutex.h ot_stats.h ot_sync.h ot_vector.h ot_clean.h ot_udp.h ot_iovec.h ot_fullscrape.h
SOURCES=opentracker.c trackerlogic.c scan_urlencoded_query.c ot_mutex.c ot_stats.c ot_sync.c ot_vector.c ot_clean.c ot_udp.c ot_iovec.c ot_fullscrape.c

OBJECTS = $(SOURCES:%.c=%.o)
OBJECTS_debug = $(SOURCES:%.c=%.debug.o)

.SUFFIXES: .debug.o .o .c

all: $(BINARY) $(BINARY).debug

CFLAGS_production = $(CFLAGS) $(OPTS_production) $(FEATURES)
CFLAGS_debug = $(CFLAGS) $(OPTS_debug) $(FEATURES)

$(BINARY): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)
	strip $@
$(BINARY).debug: $(OBJECTS_debug) $(HEADERS)
	$(CC) -o $@ $(OBJECTS_debug) $(LDFLAGS)

.c.debug.o : $(HEADERS)
	$(CC) -c -o $@ $(CFLAGS_debug) $(<:.debug.o=.c)

.c.o : $(HEADERS)
	$(CC) -c -o $@ $(CFLAGS_production) $<

clean:
	rm -rf opentracker opentracker.debug *.o *~
