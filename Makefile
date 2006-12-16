CC?=gcc
CFLAGS+=-I../libowfat -Wall -pipe -Os
LDFLAGS+=-L../libowfat/ -lowfat -s -lm

HEADERS=trackerlogic.h scan_urlencoded_query.h
SOURCES=opentracker.c trackerlogic.c scan_urlencoded_query.c

opentracker: $(SOURCES) $(HEADERS)
	$(CC) $(SOURCES) -o opentracker $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf opentracker
