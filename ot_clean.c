/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <pthread.h>
#include <unistd.h>
#include <string.h>

/* Libowfat */
#include "io.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_vector.h"
#include "ot_clean.h"
#include "ot_stats.h"

/* Returns amount of removed peers */
static ssize_t clean_single_bucket( ot_peer *peers, size_t peer_count, time_t timedout, int *removed_seeders ) {
  ot_peer *last_peer = peers + peer_count, *insert_point;
  time_t timediff;

  /* Two scan modes: unless there is one peer removed, just increase ot_peertime */
  while( peers < last_peer ) {
    if( ( timediff = timedout + OT_PEERTIME( peers ) ) >= OT_PEER_TIMEOUT )
      break;
    OT_PEERTIME( peers++ ) = timediff;
  }

  /* If we at least remove one peer, we have to copy  */
  insert_point = peers;
  while( peers < last_peer )
    if( ( timediff = timedout + OT_PEERTIME( peers ) ) < OT_PEER_TIMEOUT ) {
      OT_PEERTIME( peers ) = timediff;
      memcpy( insert_point++, peers++, sizeof(ot_peer));
    } else
      if( OT_PEERFLAG( peers++ ) & PEER_FLAG_SEEDING )
        (*removed_seeders)++;

  return peers - insert_point;
}

/* Clean a single torrent
   return 1 if torrent timed out
*/
int clean_single_torrent( ot_torrent *torrent ) {
  ot_peerlist *peer_list = torrent->peer_list;
  ot_vector *bucket_list = &peer_list->peers;
  time_t timedout = (time_t)( g_now_minutes - peer_list->base );
  int num_buckets = 1, removed_seeders = 0;

  /* No need to clean empty torrent */
  if( !timedout )
    return 0;

  /* Torrent has idled out */
  if( timedout > OT_TORRENT_TIMEOUT )
    return 1;

  /* Nothing to be cleaned here? Test if torrent is worth keeping */
  if( timedout > OT_PEER_TIMEOUT ) {
    if( !peer_list->peer_count )
      return peer_list->down_count ? 0 : 1;
    timedout = OT_PEER_TIMEOUT;
  }

  if( OT_PEERLIST_HASBUCKETS( peer_list ) ) {
    num_buckets = bucket_list->size;
    bucket_list = (ot_vector *)bucket_list->data;
  }

  while( num_buckets-- ) {
    size_t removed_peers = clean_single_bucket( bucket_list->data, bucket_list->size, timedout, &removed_seeders );
    peer_list->peer_count -= removed_peers;
    bucket_list->size     -= removed_peers;
    if( bucket_list->size < removed_peers )
      vector_fixup_peers( bucket_list );
    ++bucket_list;
  }

  peer_list->seed_count -= removed_seeders;

  /* See, if we need to convert a torrent from simple vector to bucket list */
  if( ( peer_list->peer_count > OT_PEER_BUCKET_MINCOUNT ) || OT_PEERLIST_HASBUCKETS(peer_list) )
    vector_redistribute_buckets( peer_list );

  if( peer_list->peer_count )
    peer_list->base = g_now_minutes;
  else {
    /* When we got here, the last time that torrent
     has been touched is OT_PEER_TIMEOUT Minutes before */
    peer_list->base = g_now_minutes - OT_PEER_TIMEOUT;
  }
  return 0;

}

/* Clean up all peers in current bucket, remove timedout pools and
 torrents */
static void * clean_worker( void * args ) {
  (void) args;
  while( 1 ) {
    int bucket = OT_BUCKET_COUNT;
    while( bucket-- ) {
      ot_vector *torrents_list = mutex_bucket_lock( bucket );
      size_t     toffs;
      int        delta_torrentcount = 0;

      for( toffs=0; toffs<torrents_list->size; ++toffs ) {
        ot_torrent *torrent = ((ot_torrent*)(torrents_list->data)) + toffs;
        if( clean_single_torrent( torrent ) ) {
          vector_remove_torrent( torrents_list, torrent );
          --delta_torrentcount;
          --toffs;
        }
      }
      mutex_bucket_unlock( bucket, delta_torrentcount );
      if( !g_opentracker_running )
        return NULL;
      usleep( OT_CLEAN_SLEEP );
    }
    stats_cleanup();
  }
  return NULL;
}

static pthread_t thread_id;
void clean_init( void ) {
  pthread_create( &thread_id, NULL, clean_worker, NULL );
}

void clean_deinit( void ) {
  pthread_cancel( thread_id );
}

const char *g_version_clean_c = "$Source$: $Revision$\n";
