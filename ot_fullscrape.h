/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifndef __OT_FULLSCRAPE_H__
#define __OT_FULLSCRAPE_H__

#ifdef WANT_FULLSCRAPE

void fullscrape_init( );
void fullscrape_deinit( );
void fullscrape_deliver( int64 sock, ot_tasktype tasktype );

#else

#define fullscrape_init()
#define fullscrape_deinit()

#endif

#endif
