/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __OT_MUTEX_H__
#define __OT_MUTEX_H__

void mutex_init( );
void mutex_deinit( );

ot_vector *mutex_bucket_lock( int bucket );
ot_vector *mutex_bucket_lock_by_hash( ot_hash *hash );

void mutex_bucket_unlock( int bucket );
void mutex_bucket_unlock_by_hash( ot_hash *hash );

#endif
