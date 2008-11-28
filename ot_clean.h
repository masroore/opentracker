/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifndef __OT_CLEAN_H__
#define __OT_CLEAN_H__

/* The amount of time a clean cycle should take */
#define OT_CLEAN_INTERVAL_MINUTES       2

/* So after each bucket wait 1 / OT_BUCKET_COUNT intervals */
#define OT_CLEAN_SLEEP ( ( ( OT_CLEAN_INTERVAL_MINUTES ) * 60 * 1000000 ) / ( OT_BUCKET_COUNT ) )

void clean_init( void );
void clean_deinit( void );
int  clean_single_torrent( ot_torrent *torrent );

#endif
