/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __OT_CLEAN_H__
#define __OT_CLEAN_H__

void clean_init( void );
void clean_deinit( void );

void clean_all_torrents( void );
int  clean_single_torrent( ot_torrent *torrent );

#endif
