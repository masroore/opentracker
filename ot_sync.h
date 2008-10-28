/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifndef __OT_SYNC_H__
#define __OT_SYNC_H__

#ifdef WANT_SYNC_BATCH
enum { SYNC_IN, SYNC_OUT };

void sync_init( );
void sync_deinit( );
void sync_deliver( int64 socket );

int  add_changeset_to_tracker( uint8_t *data, size_t len );
#else

#define sync_init()
#define sync_deinit()

#endif

#endif
