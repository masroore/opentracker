/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __MUTEX_H__
#define __MUTEX_H__

void mutex_init( );
void mutex_deinit( );

void mutex_bucket_lock( int bucket );
void mutex_bucket_unlock( int bucket );

#endif
