/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __OT_FULLSCRAPE_H__
#define __OT_FULLSCRAPE_H__

void fullscrape_init( );
void fullscrape_deinit( );
void fullscrape_deliver( int64 socket, ot_tasktype tasktype );

#endif
