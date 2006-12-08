CC?=gcc
CFLAGS+=-I../libowfat -Wall -pipe -g -ggdb
LDFLAGS+=-L../libowfat/ -lowfat

SOURCES=opentracker.c trackerlogic.c scan_urlencoded_query.c

opentracker: $(SOURCES)
	$(CC) $(SOURCES) -o opentracker $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf opentracker
