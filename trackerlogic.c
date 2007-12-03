/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

/* System */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

/* Libowfat */
#include "scan.h"
#include "byte.h"
#include "io.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_stats.h"
#include "ot_clean.h"
#include "ot_accesslist.h"
#include "ot_fullscrape.h"
#include "ot_sync.h"

void free_peerlist( ot_peerlist *peer_list ) {
  size_t i;
  for( i=0; i<OT_POOLS_COUNT; ++i )
    if( peer_list->peers[i].data )
      free( peer_list->peers[i].data );
#ifdef WANT_TRACKER_SYNC
  free( peer_list->changeset.data );
#endif
  free( peer_list );
}

ot_torrent *add_peer_to_torrent( ot_hash *hash, ot_peer *peer  WANT_TRACKER_SYNC_PARAM( int from_changeset ) ) {
  int         exactmatch;
  ot_torrent *torrent;
  ot_peer    *peer_dest;
  ot_vector  *torrents_list = mutex_bucket_lock_by_hash( hash ), *peer_pool;
  int         base_pool = 0;

  if( !accesslist_hashisvalid( hash ) ) {
    mutex_bucket_unlock_by_hash( hash );
    return NULL;
  }

  torrent = vector_find_or_insert( torrents_list, (void*)hash, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  if( !torrent ) {
    mutex_bucket_unlock_by_hash( hash );
    return NULL;
  }

  if( !exactmatch ) {
    /* Create a new torrent entry, then */
    memmove( &torrent->hash, hash, sizeof( ot_hash ) );

    if( !( torrent->peer_list = malloc( sizeof (ot_peerlist) ) ) ) {
      vector_remove_torrent( torrents_list, torrent );
      mutex_bucket_unlock_by_hash( hash );
      return NULL;
    }

    byte_zero( torrent->peer_list, sizeof( ot_peerlist ) );
  } else
    clean_single_torrent( torrent );

  /* Timestamp our first pool */
  torrent->peer_list->base = NOW;

  /* Sanitize flags: Whoever claims to have completed download, must be a seeder */
  if( ( OT_FLAG( peer ) & ( PEER_FLAG_COMPLETED | PEER_FLAG_SEEDING ) ) == PEER_FLAG_COMPLETED )
    OT_FLAG( peer ) ^= PEER_FLAG_COMPLETED;

#ifdef WANT_TRACKER_SYNC
  if( from_changeset ) {
    /* Check, whether peer already is in current pool, do nothing if so */
    peer_pool = &torrent->peer_list->peers[0];
    binary_search( peer, peer_pool->data, peer_pool->size, sizeof(ot_peer), OT_PEER_COMPARE_SIZE, &exactmatch );
    if( exactmatch ) {
      mutex_bucket_unlock_by_hash( hash );
      return torrent;
    }
    base_pool = 1;
  }
#endif

  peer_pool = &torrent->peer_list->peers[ base_pool ];
  peer_dest = vector_find_or_insert( peer_pool, (void*)peer, sizeof( ot_peer ), OT_PEER_COMPARE_SIZE, &exactmatch );

  /* If we hadn't had a match in current pool, create peer there and
     remove it from all older pools */
  if( !exactmatch ) {
    int i;
    memmove( peer_dest, peer, sizeof( ot_peer ) );
    torrent->peer_list->peer_count++;

    if( OT_FLAG( peer ) & PEER_FLAG_COMPLETED )
      torrent->peer_list->down_count++;

    if( OT_FLAG(peer) & PEER_FLAG_SEEDING ) {
      torrent->peer_list->seed_counts[ base_pool ]++;
      torrent->peer_list->seed_count++;
    }

    for( i= base_pool + 1; i<OT_POOLS_COUNT; ++i ) {
      switch( vector_remove_peer( &torrent->peer_list->peers[i], peer, 0 ) ) {
        case 0: continue;
        case 2: torrent->peer_list->seed_counts[i]--;
                torrent->peer_list->seed_count--;
        case 1: default:
                torrent->peer_list->peer_count--;
                mutex_bucket_unlock_by_hash( hash );
                return torrent;
      }
    }
  } else {
    if( (OT_FLAG(peer_dest) & PEER_FLAG_SEEDING ) && !(OT_FLAG(peer) & PEER_FLAG_SEEDING ) ) {
      torrent->peer_list->seed_counts[ base_pool ]--;
      torrent->peer_list->seed_count--;
    }
    if( !(OT_FLAG(peer_dest) & PEER_FLAG_SEEDING ) && (OT_FLAG(peer) & PEER_FLAG_SEEDING ) ) {
      torrent->peer_list->seed_counts[ base_pool ]++;
      torrent->peer_list->seed_count++;
    }
    if( !(OT_FLAG( peer_dest ) & PEER_FLAG_COMPLETED ) && (OT_FLAG( peer ) & PEER_FLAG_COMPLETED ) )
      torrent->peer_list->down_count++;
    if( OT_FLAG( peer_dest ) & PEER_FLAG_COMPLETED )
      OT_FLAG( peer ) |= PEER_FLAG_COMPLETED;

    memmove( peer_dest, peer, sizeof( ot_peer ) );
  }

  mutex_bucket_unlock_by_hash( hash );
  return torrent;
}

/* Compiles a list of random peers for a torrent
   * reply must have enough space to hold 92+6*amount bytes
   * Selector function can be anything, maybe test for seeds, etc.
   * RANDOM may return huge values
   * does not yet check not to return self
*/
size_t return_peers_for_torrent( ot_hash *hash, size_t amount, char *reply, int is_tcp ) {
  char        *r = reply;
  int          exactmatch;
  ot_vector   *torrents_list = mutex_bucket_lock_by_hash( hash );
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  ot_peerlist *peer_list = torrent->peer_list;
  size_t       index;

  if( !torrent ) {
    mutex_bucket_unlock_by_hash( hash );
    return 0;
  }

  if( peer_list->peer_count < amount )
    amount = peer_list->peer_count;

  if( is_tcp )
    r += sprintf( r, "d8:completei%zde10:incompletei%zde8:intervali%ie5:peers%zd:", peer_list->seed_count, peer_list->peer_count-peer_list->seed_count, OT_CLIENT_REQUEST_INTERVAL_RANDOM, 6*amount );
  else {
    *(uint32_t*)(r+0) = htonl( OT_CLIENT_REQUEST_INTERVAL_RANDOM );
    *(uint32_t*)(r+4) = htonl( peer_list->peer_count );
    *(uint32_t*)(r+8) = htonl( peer_list->seed_count );
    r += 12;
  }

  if( amount ) {
    unsigned int pool_offset, pool_index = 0;;
    unsigned int shifted_pc = peer_list->peer_count;
    unsigned int shifted_step = 0;
    unsigned int shift = 0;

    /* Make fixpoint arithmetic as exact as possible */
#define MAXPRECBIT (1<<(8*sizeof(int)-3))
    while( !(shifted_pc & MAXPRECBIT ) ) { shifted_pc <<= 1; shift++; }
    shifted_step = shifted_pc/amount;
#undef MAXPRECBIT

    /* Initialize somewhere in the middle of peers so that
       fixpoint's aliasing doesn't alway miss the same peers */
    pool_offset = random() % peer_list->peer_count;

    for( index = 0; index < amount; ++index ) {
      /* This is the aliased, non shifted range, next value may fall into */
      unsigned int diff = ( ( ( index + 1 ) * shifted_step ) >> shift ) -
                          ( (   index       * shifted_step ) >> shift );
      pool_offset += 1 + random() % diff;

      while( pool_offset >= peer_list->peers[pool_index].size ) {
        pool_offset -= peer_list->peers[pool_index].size;
        pool_index = ( pool_index + 1 ) % OT_POOLS_COUNT;
      }

      memmove( r, ((ot_peer*)peer_list->peers[pool_index].data) + pool_offset, 6 );
      r += 6;
    }
  }
  if( is_tcp )
    *r++ = 'e';

  mutex_bucket_unlock_by_hash( hash );
  return r - reply;
}

/* Fetches scrape info for a specific torrent */
size_t return_udp_scrape_for_torrent( ot_hash *hash, char *reply ) {
  int          exactmatch;
  ot_vector   *torrents_list = mutex_bucket_lock_by_hash( hash );
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );

  if( !exactmatch ) {
    memset( reply, 0, 12);
  } else {
    uint32_t *r = (uint32_t*) reply;

    if( clean_single_torrent( torrent ) ) {
      vector_remove_torrent( torrents_list, torrent );
      memset( reply, 0, 12);
    } else {
      r[0] = htonl( torrent->peer_list->seed_count );
      r[1] = htonl( torrent->peer_list->down_count );
      r[2] = htonl( torrent->peer_list->peer_count-torrent->peer_list->seed_count );
    }
  }
  mutex_bucket_unlock_by_hash( hash );
  return 12;
}

/* Fetches scrape info for a specific torrent */
size_t return_tcp_scrape_for_torrent( ot_hash *hash_list, int amount, char *reply ) {
  char        *r = reply;
  int          exactmatch, i;

  r += sprintf( r, "d5:filesd" );

  for( i=0; i<amount; ++i ) {
    ot_hash     *hash = hash_list + i;
    ot_vector   *torrents_list = mutex_bucket_lock_by_hash( hash );
    ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );

    if( exactmatch ) {
      if( clean_single_torrent( torrent ) ) {
        vector_remove_torrent( torrents_list, torrent );
      } else {
        memmove( r, "20:", 3 ); memmove( r+3, hash, 20 );
        r += sprintf( r+23, "d8:completei%zde10:downloadedi%zde10:incompletei%zdee",
          torrent->peer_list->seed_count, torrent->peer_list->down_count, torrent->peer_list->peer_count-torrent->peer_list->seed_count ) + 23;
      }
    }
    mutex_bucket_unlock_by_hash( hash );
  }

  *r++ = 'e'; *r++ = 'e';
  return r - reply;
}

size_t remove_peer_from_torrent( ot_hash *hash, ot_peer *peer, char *reply, int is_tcp ) {
  int          exactmatch;
  size_t       index;
  ot_vector   *torrents_list = mutex_bucket_lock_by_hash( hash );
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  ot_peerlist *peer_list;

  if( !exactmatch ) {
    mutex_bucket_unlock_by_hash( hash );

    if( is_tcp )
      return sprintf( reply, "d8:completei0e10:incompletei0e8:intervali%ie5:peers0:e", OT_CLIENT_REQUEST_INTERVAL_RANDOM );

    /* Create fake packet to satisfy parser on the other end */
    ((uint32_t*)reply)[2] = htonl( OT_CLIENT_REQUEST_INTERVAL_RANDOM );
    ((uint32_t*)reply)[3] = ((uint32_t*)reply)[4] = 0;
    return (size_t)20;
  }

  peer_list = torrent->peer_list;
  for( index = 0; index<OT_POOLS_COUNT; ++index ) {
    switch( vector_remove_peer( &peer_list->peers[index], peer, index == 0 ) ) {
      case 0: continue;
      case 2: peer_list->seed_counts[index]--;
              peer_list->seed_count--;
      case 1: default:
              peer_list->peer_count--;
              goto exit_loop;
    }
  }

exit_loop:

  if( is_tcp ) {
    size_t reply_size = sprintf( reply, "d8:completei%zde10:incompletei%zde8:intervali%ie5:peers0:e", peer_list->seed_count, peer_list->peer_count - peer_list->seed_count, OT_CLIENT_REQUEST_INTERVAL_RANDOM );
    mutex_bucket_unlock_by_hash( hash );
    return reply_size;
  }

  /* else { Handle UDP reply */
  ((uint32_t*)reply)[2] = htonl( OT_CLIENT_REQUEST_INTERVAL_RANDOM );
  ((uint32_t*)reply)[3] = peer_list->peer_count - peer_list->seed_count;
  ((uint32_t*)reply)[4] = peer_list->seed_count;

  mutex_bucket_unlock_by_hash( hash );
  return (size_t)20;
}

int trackerlogic_init( const char * const serverdir ) {
  if( serverdir && chdir( serverdir ) ) {
    fprintf( stderr, "Could not chdir() to %s\n", serverdir );
    return -1;
  }

  srandom( time(NULL) );

  /* Initialise background worker threads */
  mutex_init( );
  clean_init( );
  fullscrape_init( );
#ifdef WANT_TRACKER_SYNC
  sync_init( );
#endif
  stats_init( );
  return 0;
}

void trackerlogic_deinit( void ) {
  int bucket;
  size_t j;

  /* Free all torrents... */
  for(bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    if( torrents_list->size ) {
      for( j=0; j<torrents_list->size; ++j ) {
        ot_torrent *torrent = ((ot_torrent*)(torrents_list->data)) + j;
        free_peerlist( torrent->peer_list );
      }
      free( torrents_list->data );
    }
    mutex_bucket_unlock( bucket );
  }

  /* Deinitialise background worker threads */
  stats_deinit( );
#ifdef WANT_TRACKER_SYNC
  sync_deinit( );
#endif
  fullscrape_deinit( );
  clean_deinit( );
  mutex_deinit( );
}
