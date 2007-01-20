CC?=gcc
FEATURES=#-D_DEBUG_FDS -DWANT_IP_FROM_QUERY_STRING -DWANT_BLACKLIST -DWANT_CLOSED_TRACKER
#DEBUG_OPTS=-g -ggdb -pg # -fprofile-arcs -ftest-coverage
DEBUG_OPTS=-s -Os
CFLAGS+=-I../libowfat -Wall -pipe # -pedantic -ansi
LDFLAGS+=-L../libowfat/ -lowfat -lm

HEADERS=trackerlogic.h scan_urlencoded_query.h
SOURCES=opentracker.c trackerlogic.c scan_urlencoded_query.c

opentracker: $(SOURCES) $(HEADERS)
	$(CC) $(SOURCES) -o opentracker $(CFLAGS) $(FEATURES) $(DEBUG_OPTS) $(LDFLAGS)

clean:
	rm -rf opentracker
