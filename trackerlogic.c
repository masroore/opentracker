/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

/* Libowfat */
#include "byte.h"
#include "io.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_stats.h"
#include "ot_clean.h"
#include "ot_accesslist.h"
#include "ot_fullscrape.h"
#include "ot_livesync.h"

void free_peerlist( ot_peerlist *peer_list ) {
  if( peer_list->peers.data ) {
    if( OT_PEERLIST_HASBUCKETS( peer_list ) ) {
      ot_vector *bucket_list = (ot_vector*)(peer_list->peers.data);

      while( peer_list->peers.size-- )
        free( bucket_list++->data );
    }
    free( peer_list->peers.data );
  }
  free( peer_list );
}

#ifdef _DEBUG_PEERID
extern size_t g_this_peerid_len;
extern char  *g_this_peerid_data;
#endif

ot_torrent *add_peer_to_torrent( ot_hash *hash, ot_peer *peer  WANT_SYNC_PARAM( int from_sync ) ) {
  int         exactmatch;
  ot_torrent *torrent;
  ot_peer    *peer_dest;
  ot_vector  *torrents_list = mutex_bucket_lock_by_hash( hash );

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
    int i; for(i=0;i<20;i+=4) WRITE32(&torrent->hash,i,READ32(hash,i));
    
    if( !( torrent->peer_list = malloc( sizeof (ot_peerlist) ) ) ) {
      vector_remove_torrent( torrents_list, torrent );
      mutex_bucket_unlock_by_hash( hash );
      return NULL;
    }

    byte_zero( torrent->peer_list, sizeof( ot_peerlist ) );
  } else
    clean_single_torrent( torrent );

  torrent->peer_list->base = g_now_minutes;

  /* Check for peer in torrent */
  peer_dest = vector_find_or_insert_peer( &(torrent->peer_list->peers), peer, &exactmatch );
  if( !peer_dest ) {
    mutex_bucket_unlock_by_hash( hash );
    return NULL;
  }

  /* Tell peer that it's fresh */
  OT_PEERTIME( peer ) = 0;

  /* Sanitize flags: Whoever claims to have completed download, must be a seeder */
  if( ( OT_PEERFLAG( peer ) & ( PEER_FLAG_COMPLETED | PEER_FLAG_SEEDING ) ) == PEER_FLAG_COMPLETED )
    OT_PEERFLAG( peer ) ^= PEER_FLAG_COMPLETED;

  /* If we hadn't had a match create peer there */
  if( !exactmatch ) {

#ifdef WANT_SYNC_LIVE
    if( !from_sync )
      livesync_tell( hash, peer );
    else
      OT_PEERFLAG( peer ) |= PEER_FLAG_FROM_SYNC;
#endif

    torrent->peer_list->peer_count++;
    if( OT_PEERFLAG(peer) & PEER_FLAG_COMPLETED )
      torrent->peer_list->down_count++;
    if( OT_PEERFLAG(peer) & PEER_FLAG_SEEDING )
      torrent->peer_list->seed_count++;

  } else {
    stats_issue_event( EVENT_RENEW, 0, OT_PEERTIME( peer_dest ) );

#ifdef _DEBUG_PEERID
    if( OT_PEERTIME( peer_dest ) < 2 ) {
      uint8_t *_ip = (uint8_t*)peer_dest;
      int i;
      for( i=0;i<20;++i)printf("%02X",(*hash)[i]);
      if( g_this_peerid_data ) g_this_peerid_data[g_this_peerid_len] = 0;
      printf( " %d.%d.%d.%d:%d\t%d %02X %s\n", _ip[0], _ip[1], _ip[2], _ip[3], OT_PEERTIME( peer_dest ), *(uint16_t*)( ((char*)peer_dest)+4 ), OT_PEERFLAG(peer_dest), g_this_peerid_data ? g_this_peerid_data : "-" );
    }
#endif
    
#ifdef WANT_SYNC_LIVE
    /* Won't live sync peers that come back too fast. Only exception:
       fresh "completed" reports */
    if( !from_sync ) {
      if( OT_PEERTIME( peer_dest ) > OT_CLIENT_SYNC_RENEW_BOUNDARY ||
         ( !(OT_PEERFLAG(peer_dest) & PEER_FLAG_COMPLETED ) && (OT_PEERFLAG(peer) & PEER_FLAG_COMPLETED ) ) )
        livesync_tell( hash, peer );
    }
#endif
    
    if(  (OT_PEERFLAG(peer_dest) & PEER_FLAG_SEEDING )   && !(OT_PEERFLAG(peer) & PEER_FLAG_SEEDING ) )
      torrent->peer_list->seed_count--;
    if( !(OT_PEERFLAG(peer_dest) & PEER_FLAG_SEEDING )   &&  (OT_PEERFLAG(peer) & PEER_FLAG_SEEDING ) )
      torrent->peer_list->seed_count++;
    if( !(OT_PEERFLAG(peer_dest) & PEER_FLAG_COMPLETED ) &&  (OT_PEERFLAG(peer) & PEER_FLAG_COMPLETED ) )
      torrent->peer_list->down_count++;
    if(   OT_PEERFLAG(peer_dest) & PEER_FLAG_COMPLETED )
      OT_PEERFLAG( peer ) |= PEER_FLAG_COMPLETED;
  }

  *(uint64_t*)(peer_dest) = *(uint64_t*)(peer);
#ifdef WANT_SYNC
  /* In order to avoid an unlock/lock between add_peers and return_peers,
     we only unlock the bucket if return_peers won't do the job: either
     if we return NULL or if no reply is expected, i.e. when called
     from livesync code. */
  if( from_sync )
    mutex_bucket_unlock_by_hash( hash );
#endif
  return torrent;
}

static size_t return_peers_all( ot_peerlist *peer_list, char *reply ) {
  unsigned int bucket, num_buckets = 1;
  ot_vector * bucket_list = &peer_list->peers;
  char      * r = reply;

  if( OT_PEERLIST_HASBUCKETS(peer_list) ) {
    num_buckets = bucket_list->size;
    bucket_list = (ot_vector *)bucket_list->data;
  }

  for( bucket = 0; bucket<num_buckets; ++bucket ) {
    ot_peer * peers = (ot_peer*)bucket_list[bucket].data;
    size_t    peer_count = bucket_list[bucket].size;
    while( peer_count-- ) {
      WRITE32(r,0,READ32(peers,0));
      WRITE16(r,4,READ16(peers++,4));
      r+=6;
    }
  }

  return r - reply;
}

static size_t return_peers_selection( ot_peerlist *peer_list, size_t amount, char *reply ) {
  unsigned int bucket_offset, bucket_index = 0, num_buckets = 1;
  ot_vector  * bucket_list = &peer_list->peers;
  unsigned int shifted_pc = peer_list->peer_count;
  unsigned int shifted_step = 0;
  unsigned int shift = 0;
  char       * r = reply;

  if( OT_PEERLIST_HASBUCKETS(peer_list) ) {
    num_buckets = bucket_list->size;
    bucket_list = (ot_vector *)bucket_list->data;
  }
    
  /* Make fixpoint arithmetic as exact as possible */
#define MAXPRECBIT (1<<(8*sizeof(int)-3))
  while( !(shifted_pc & MAXPRECBIT ) ) { shifted_pc <<= 1; shift++; }
  shifted_step = shifted_pc/amount;
#undef MAXPRECBIT

  /* Initialize somewhere in the middle of peers so that
   fixpoint's aliasing doesn't alway miss the same peers */
  bucket_offset = random() % peer_list->peer_count;

  while( amount-- ) {
    ot_peer * peer;

    /* This is the aliased, non shifted range, next value may fall into */
    unsigned int diff = ( ( ( amount + 1 ) * shifted_step ) >> shift ) -
                        ( (   amount       * shifted_step ) >> shift );
    bucket_offset += 1 + random() % diff;

    while( bucket_offset >= bucket_list[bucket_index].size ) {
      bucket_offset -= bucket_list[bucket_index].size;
      bucket_index = ( bucket_index + 1 ) % num_buckets;
    }
    peer = ((ot_peer*)bucket_list[bucket_index].data) + bucket_offset;
    WRITE32(r,0,READ32(peer,0));
    WRITE16(r,4,READ16(peer,4));
    r+=6;
  }
  return r - reply;
}

/* Compiles a list of random peers for a torrent
   * reply must have enough space to hold 92+6*amount bytes
   * does not yet check not to return self
   * the bucket, torrent resides in has been locked by the
     add_peer call, the ot_torrent * was gathered from, so we
     have to unlock it here.
*/
size_t return_peers_for_torrent( ot_torrent *torrent, size_t amount, char *reply, PROTO_FLAG proto ) {
  ot_peerlist *peer_list = torrent->peer_list;
  char        *r = reply;

  if( amount > peer_list->peer_count )
    amount = peer_list->peer_count;
  
  if( proto == FLAG_TCP ) {
    int erval = OT_CLIENT_REQUEST_INTERVAL_RANDOM;
    r += sprintf( r, "d8:completei%zde10:downloadedi%zde10:incompletei%zde8:intervali%ie12:min intervali%ie5:peers%zd:", peer_list->seed_count, peer_list->down_count, peer_list->peer_count-peer_list->seed_count, erval, erval/2, 6*amount );
  } else {
    *(uint32_t*)(r+0) = htonl( OT_CLIENT_REQUEST_INTERVAL_RANDOM );
    *(uint32_t*)(r+4) = htonl( peer_list->peer_count );
    *(uint32_t*)(r+8) = htonl( peer_list->seed_count );
    r += 12;
  }

  if( amount ) {
    if( amount == peer_list->peer_count )
      r += return_peers_all( peer_list, r );
    else
      r += return_peers_selection( peer_list, amount, r );
  }

  if( proto == FLAG_TCP )
    *r++ = 'e';

  mutex_bucket_unlock_by_hash( &torrent->hash );
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
        int j;
        *r++='2';*r++='0';*r++=':';
        for(j=0;j<20;j+=4) WRITE32(r,j,READ32(hash,j)); r += 20;
        r += sprintf( r, "d8:completei%zde10:downloadedi%zde10:incompletei%zdee",
          torrent->peer_list->seed_count, torrent->peer_list->down_count, torrent->peer_list->peer_count-torrent->peer_list->seed_count );
      }
    }
    mutex_bucket_unlock_by_hash( hash );
  }

  *r++ = 'e'; *r++ = 'e';
  return r - reply;
}

static ot_peerlist dummy_list;
size_t remove_peer_from_torrent( ot_hash *hash, ot_peer *peer, char *reply, PROTO_FLAG proto ) {
  int          exactmatch;
  size_t       reply_size = 0;
  ot_vector   *torrents_list = mutex_bucket_lock_by_hash( hash );
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  ot_peerlist *peer_list = &dummy_list;

#ifdef WANT_SYNC_LIVE
  if( proto != FLAG_MCA ) {
    OT_PEERFLAG( peer ) |= PEER_FLAG_STOPPED;
    livesync_tell( hash, peer );
  }
#endif

  if( exactmatch ) {
    peer_list = torrent->peer_list;
    switch( vector_remove_peer( &peer_list->peers, peer ) ) {
      case 2:  peer_list->seed_count--; /* Fall throughs intended */
      case 1:  peer_list->peer_count--; /* Fall throughs intended */
      default: break;
    }
  }

  if( proto == FLAG_TCP ) {
    int erval = OT_CLIENT_REQUEST_INTERVAL_RANDOM;
    reply_size = sprintf( reply, "d8:completei%zde10:incompletei%zde8:intervali%ie12:min intervali%ie5:peers0:e", peer_list->seed_count, peer_list->peer_count - peer_list->seed_count, erval, erval / 2 );
  }
  
  /* Handle UDP reply */
  if( proto == FLAG_UDP ) {
    ((uint32_t*)reply)[2] = htonl( OT_CLIENT_REQUEST_INTERVAL_RANDOM );
    ((uint32_t*)reply)[3] = htonl( peer_list->peer_count - peer_list->seed_count );
    ((uint32_t*)reply)[4] = htonl( peer_list->seed_count);
    reply_size = 20;
  }

  mutex_bucket_unlock_by_hash( hash );
  return reply_size;
}

void exerr( char * message ) {
  fprintf( stderr, "%s\n", message );
  exit( 111 );
}

int trackerlogic_init( const char * const serverdir ) {
  if( serverdir && chdir( serverdir ) ) {
    fprintf( stderr, "Could not chdir() to %s, because %s\n", serverdir, strerror(errno) );
    return -1;
  }

  srandom( time(NULL) );
  g_tracker_id = random();

  /* Initialise background worker threads */
  mutex_init( );
  clean_init( );
  fullscrape_init( );
  accesslist_init( );
  livesync_init( );
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
  livesync_deinit( );
  accesslist_deinit( );
  fullscrape_deinit( );
  clean_deinit( );
  /* Release mutexes */
  mutex_deinit( );
}

const char *g_version_trackerlogic_c = "$Source$: $Revision$\n";
