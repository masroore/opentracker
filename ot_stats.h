/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __OT_STATS_H__
#define __OT_STATS_H__

enum { STATS_CONNS, STATS_PEERS, STATS_TOP5, STATS_DMEM, STATS_TCP, STATS_UDP, STATS_SLASH24S, SYNC_IN, SYNC_OUT, STATS_FULLSCRAPE };

size_t return_stats_for_tracker( char *reply, int mode );
size_t return_stats_for_slash24s( char *reply, size_t amount, ot_dword thresh );
size_t return_memstat_for_tracker( char **reply );

#endif
