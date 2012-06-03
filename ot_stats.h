/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifndef __OT_STATS_H__
#define __OT_STATS_H__

typedef enum {
  EVENT_ACCEPT,
  EVENT_READ,
  EVENT_CONNECT,      /* UDP only */
  EVENT_ANNOUNCE,
  EVENT_COMPLETED,
  EVENT_RENEW,
  EVENT_SYNC,
  EVENT_SCRAPE,
  EVENT_FULLSCRAPE_REQUEST,
  EVENT_FULLSCRAPE_REQUEST_GZIP,
  EVENT_FULLSCRAPE,   /* TCP only */
  EVENT_FAILED,
  EVENT_BUCKET_LOCKED,
  EVENT_WOODPECKER,
  EVENT_CONNID_MISSMATCH
} ot_status_event;

enum {
  CODE_HTTPERROR_302,
  CODE_HTTPERROR_400,
  CODE_HTTPERROR_400_PARAM,
  CODE_HTTPERROR_400_COMPACT,
  CODE_HTTPERROR_402_NOTMODEST,
  CODE_HTTPERROR_403_IP,
  CODE_HTTPERROR_404,
  CODE_HTTPERROR_500,

  CODE_HTTPERROR_COUNT
};

void   stats_issue_event( ot_status_event event, PROTO_FLAG proto, uintptr_t event_data );
void   stats_deliver( int64 sock, int tasktype );
void   stats_cleanup();
size_t return_stats_for_tracker( char *reply, int mode, int format );
size_t stats_return_tracker_version( char *reply );
void   stats_init( );
void   stats_deinit( );

#endif
