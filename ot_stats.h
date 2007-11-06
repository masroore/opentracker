/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __OT_STATS_H__
#define __OT_STATS_H__

enum { STATS_CONNS, STATS_PEERS, STATS_TOP5, STATS_TCP, STATS_UDP, STATS_SLASH24S, STATS_FULLSCRAPE };
typedef enum {
  EVENT_ACCEPT,
  EVENT_READ,
  EVENT_CONNECT,      /* UDP only */
  EVENT_ANNOUNCE,
  EVENT_SCRAPE,
  EVENT_FULLSCRAPE,   /* TCP only */
  EVENT_FAILED_400,
  EVENT_FAILED_404,
  EVENT_FAILED_505
} ot_status_event;

size_t return_stats_for_tracker( char *reply, int mode, int format );
void stats_issue_event( ot_status_event event, int is_tcp, size_t event_data );

#endif
