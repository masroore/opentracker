CC?=gcc
CFLAGS+=-I../libowfat -Wall -pipe -Os -DWANT_BLACKLIST -DWANT_CLOSED_TRACKER # -DWANT_IP_FROM_QUERY_STRING -g -ggdb
LDFLAGS+=-L../libowfat/ -lowfat -s -lm

HEADERS=trackerlogic.h scan_urlencoded_query.h
SOURCES=opentracker.c trackerlogic.c scan_urlencoded_query.c

opentracker: $(SOURCES) $(HEADERS)
	$(CC) $(SOURCES) -o opentracker $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf opentracker
