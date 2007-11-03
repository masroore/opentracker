/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <pthread.h>
#include <stdio.h>

#include "trackerlogic.h"
#include "mutex.h"

static int bucket_locklist[ OT_MAX_THREADS ];
static int bucket_locklist_count = 0;
static pthread_mutex_t bucket_mutex;
static pthread_cond_t bucket_being_unlocked;

static int bucket_check( int bucket ) {
  /* C should come with auto-i ;) */
  int i;

  /* No more space to acquire lock to bucket -- should not happen */
  if( bucket_locklist_count == OT_MAX_THREADS ) {
    fprintf( stderr, "More lock requests than mutexes. Consult source code.\n" );
    return -1;
  }

  /* See, if bucket is already locked */
  for( i=0; i<bucket_locklist_count; ++i )
    if( bucket_locklist[ i ] == bucket )
      return -1;

  return 0;
}

static void bucket_push( int bucket ) {
  bucket_locklist[ bucket_locklist_count++ ] = bucket;
}

static void bucket_remove( int bucket ) {
  int i = 0;

  while( ( i < bucket_locklist_count ) && ( bucket_locklist[ i ] != bucket ) )
    ++i;

  if( i == bucket_locklist_count ) {
    fprintf( stderr, "Request to unlock bucket that was never lock. Consult source code.\n" );
    return;
  }

  for( ; i < bucket_locklist_count - 1; ++i )
    bucket_locklist[ i ] = bucket_locklist[ i + 1 ];

  --bucket_locklist_count;
}

void mutex_bucket_lock( int bucket ) {
  pthread_mutex_lock( &bucket_mutex );
  while( !bucket_check( bucket ) )
    pthread_cond_wait( &bucket_being_unlocked, &bucket_mutex );
  bucket_push( bucket );
  pthread_mutex_unlock( &bucket_mutex );
}

void mutex_bucket_unlock( int bucket ) {
  pthread_mutex_lock( &bucket_mutex );
  bucket_remove( bucket );
  pthread_cond_broadcast( &bucket_being_unlocked );
  pthread_mutex_unlock( &bucket_mutex );
}   

void mutex_init( ) {
  pthread_mutex_init(&bucket_mutex, NULL);
  pthread_cond_init (&bucket_being_unlocked, NULL);
}

void mutex_deinit( ) {
  pthread_mutex_destroy(&bucket_mutex);
  pthread_cond_destroy(&bucket_being_unlocked);
}
