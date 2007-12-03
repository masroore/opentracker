/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

/* System */
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/uio.h>

/* Libowfat */
#include "byte.h"
#include "io.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"

/* Clean a single torrent
   return 1 if torrent timed out
*/
int clean_single_torrent( ot_torrent *torrent ) {
  ot_peerlist *peer_list = torrent->peer_list;
  size_t peers_count = 0, seeds_count;
  time_t timedout = (int)( NOW - peer_list->base );
  int i;
#ifdef WANT_TRACKER_SYNC
  char *new_peers;
#endif

  if( !timedout )
    return 0;

  /* Torrent has idled out */
  if( timedout > OT_TORRENT_TIMEOUT )
    return 1;

  /* Nothing to be cleaned here? Test if torrent is worth keeping */
  if( timedout > OT_POOLS_COUNT ) {
    if( !peer_list->peer_count )
      return peer_list->down_count ? 0 : 1;
    timedout = OT_POOLS_COUNT;
  }

  /* Release vectors that have timed out */
  for( i = OT_POOLS_COUNT - timedout; i < OT_POOLS_COUNT; ++i )
    free( peer_list->peers[i].data);

  /* Shift vectors back by the amount of pools that were shifted out */
  memmove( peer_list->peers + timedout, peer_list->peers, sizeof( ot_vector ) * ( OT_POOLS_COUNT - timedout ) );
  byte_zero( peer_list->peers, sizeof( ot_vector ) * timedout );

  /* Shift back seed counts as well */
  memmove( peer_list->seed_counts + timedout, peer_list->seed_counts, sizeof( size_t ) * ( OT_POOLS_COUNT - timedout ) );
  byte_zero( peer_list->seed_counts, sizeof( size_t ) * timedout );

#ifdef WANT_TRACKER_SYNC
  /* Save the block modified within last OT_POOLS_TIMEOUT */
  if( peer_list->peers[1].size &&
    ( new_peers = realloc( peer_list->changeset.data, sizeof( ot_peer ) * peer_list->peers[1].size ) ) )
  {
    memmove( new_peers, peer_list->peers[1].data, peer_list->peers[1].size );
    peer_list->changeset.data = new_peers;
    peer_list->changeset.size = sizeof( ot_peer ) * peer_list->peers[1].size;
  } else {
    free( peer_list->changeset.data );

    memset( &peer_list->changeset, 0, sizeof( ot_vector ) );
  }
#endif

  peers_count = seeds_count = 0;
  for( i = 0; i < OT_POOLS_COUNT; ++i ) {
    peers_count += peer_list->peers[i].size;
    seeds_count += peer_list->seed_counts[i];
  }
  peer_list->seed_count = seeds_count;
  peer_list->peer_count = peers_count;

  if( peers_count )
    peer_list->base = NOW;
  else {
    /* When we got here, the last time that torrent
       has been touched is OT_POOLS_COUNT units before */
    peer_list->base = NOW - OT_POOLS_COUNT;
  }
  return 0;
}

static void clean_make() {
  int bucket;

  for( bucket = OT_BUCKET_COUNT - 1; bucket >= 0; --bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    size_t     toffs;

    for( toffs=0; toffs<torrents_list->size; ++toffs ) {
      ot_torrent *torrent = ((ot_torrent*)(torrents_list->data)) + toffs;
      if( clean_single_torrent( torrent ) ) {
        vector_remove_torrent( torrents_list, torrent );
        --toffs; continue;
      }
    }
    mutex_bucket_unlock( bucket );
  }
}

/* Clean up all peers in current bucket, remove timedout pools and
   torrents */
static void * clean_worker( void * args ) {
  args = args;
  while( 1 ) {
    ot_tasktype tasktype = TASK_CLEAN;
    ot_taskid   taskid   = mutex_workqueue_poptask( &tasktype );
    clean_make(  );
    mutex_workqueue_pushsuccess( taskid );
  }
  return NULL;
}

void clean_all_torrents( ) {
  mutex_workqueue_pushtask( 0, TASK_CLEAN );
}

static pthread_t thread_id;
void clean_init( void ) {
  pthread_create( &thread_id, NULL, clean_worker, NULL );
}

void clean_deinit( void ) {
  pthread_cancel( thread_id );
}
