/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include "trackerlogic.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <glob.h>

#include <errno.h>
#include "scan.h"
#include "byte.h"
#include "mutex.h"

/* GLOBAL VARIABLES */

/* We maintain a list of 1024 pointers to sorted list of ot_torrent structs
   Sort key is, of course, its hash */
#define OT_BUCKET_COUNT 1024
static ot_vector all_torrents[OT_BUCKET_COUNT];
static ot_time   all_torrents_clean[OT_BUCKET_COUNT];
#if defined ( WANT_BLACKLISTING ) || defined( WANT_CLOSED_TRACKER )
static ot_vector accesslist;
#define WANT_ACCESS_CONTROL
#endif

static int clean_single_torrent( ot_torrent *torrent );

/* these functions protect our buckets from other threads that
   try to commit announces or clean up */
static ot_vector *lock_bucket_by_hash( ot_hash *hash ) {
  unsigned char *local_hash = hash[0];
  int bucket = ( local_hash[0] << 2 ) | ( local_hash[1] >> 6 );

  /* Can block */
  mutex_bucket_lock( bucket );

  return all_torrents + bucket;
}

static void *unlock_bucket_by_hash( ot_hash *hash ) {
  unsigned char *local_hash = hash[0];
  int bucket = ( local_hash[0] << 2 ) | ( local_hash[1] >> 6 );
  mutex_bucket_unlock( bucket );

  /* To make caller's code look better, allow
     return unlock_bucket_by_hash() */
  return NULL;
}

/* Converter function from memory to human readable hex strings
   - definitely not thread safe!!!
*/
static char ths[2+2*20]="-";static char*to_hex(ot_byte*s){const char*m="0123456789ABCDEF";char*e=ths+41;char*t=ths+1;while(t<e){*t++=m[*s>>4];*t++=m[*s++&15];}*t=0;return ths+1;}

/* This function gives us a binary search that returns a pointer, even if
   no exact match is found. In that case it sets exactmatch 0 and gives
   calling functions the chance to insert data
*/
static void *binary_search( const void * const key, const void * base, const size_t member_count, const size_t member_size,
                            size_t compare_size, int *exactmatch ) {
  size_t mc = member_count;
  ot_byte *lookat = ((ot_byte*)base) + member_size * (member_count >> 1);
  *exactmatch = 1;

  while( mc ) {
    int cmp = memcmp( lookat, key, compare_size);
    if (cmp == 0) return (void *)lookat;
    if (cmp < 0) {
      base = (void*)(lookat + member_size);
      --mc;
    }
    mc >>= 1;
    lookat = ((ot_byte*)base) + member_size * (mc >> 1);
  }
  *exactmatch = 0;
  return (void*)lookat;
}

/* This is the generic insert operation for our vector type.
   It tries to locate the object at "key" with size "member_size" by comparing its first "compare_size" bytes with
   those of objects in vector. Our special "binary_search" function does that and either returns the match or a
   pointer to where the object is to be inserted. vector_find_or_insert makes space for the object and copies it,
   if it wasn't found in vector. Caller needs to check the passed "exactmatch" variable to see, whether an insert
   took place. If resizing the vector failed, NULL is returned, else the pointer to the object in vector.
*/
static void *vector_find_or_insert( ot_vector *vector, void *key, size_t member_size, size_t compare_size, int *exactmatch ) {
  ot_byte *match = binary_search( key, vector->data, vector->size, member_size, compare_size, exactmatch );

  if( *exactmatch ) return match;

  if( vector->size + 1 >= vector->space ) {
    size_t   new_space = vector->space ? OT_VECTOR_GROW_RATIO * vector->space : OT_VECTOR_MIN_MEMBERS;
    ot_byte *new_data = realloc( vector->data, new_space * member_size );
    if( !new_data ) return NULL;

    /* Adjust pointer if it moved by realloc */
    match = new_data + (match - (ot_byte*)vector->data);

    vector->data = new_data;
    vector->space = new_space;
  }
  memmove( match + member_size, match, ((ot_byte*)vector->data) + member_size * vector->size - match );
  vector->size++;
  return match;
}

/* This is the non-generic delete from vector-operation specialized for peers in pools.
   Set hysteresis == 0 if you expect the vector not to ever grow again.
   It returns 0 if no peer was found (and thus not removed)
              1 if a non-seeding peer was removed
              2 if a seeding peer was removed
*/
static int vector_remove_peer( ot_vector *vector, ot_peer *peer, int hysteresis ) {
  int      exactmatch;
  size_t   shrink_thresh = hysteresis ? OT_VECTOR_SHRINK_THRESH : OT_VECTOR_SHRINK_RATIO;
  ot_peer *end = ((ot_peer*)vector->data) + vector->size;
  ot_peer *match;

  if( !vector->size ) return 0;
  match = binary_search( peer, vector->data, vector->size, sizeof( ot_peer ), OT_PEER_COMPARE_SIZE, &exactmatch );

  if( !exactmatch ) return 0;
  exactmatch = ( OT_FLAG( match ) & PEER_FLAG_SEEDING ) ? 2 : 1;
  memmove( match, match + 1, sizeof(ot_peer) * ( end - match - 1 ) );
  if( ( --vector->size * shrink_thresh < vector->space ) && ( vector->space > OT_VECTOR_MIN_MEMBERS ) ) {
    vector->space /= OT_VECTOR_SHRINK_RATIO;
    vector->data = realloc( vector->data, vector->space * sizeof( ot_peer ) );
  }
  if( !vector->size ) {
    /* for peer pools its safe to let them go,
       in 999 of 1000 this happens in older pools, that won't ever grow again */
    free( vector->data );
    vector->data = NULL;
    vector->space = 0;
  }
  return exactmatch;
}

static void free_peerlist( ot_peerlist *peer_list ) {
  size_t i;
  for( i=0; i<OT_POOLS_COUNT; ++i )
    if( peer_list->peers[i].data )
      free( peer_list->peers[i].data );
#ifdef WANT_TRACKER_SYNC
  free( peer_list->changeset.data );
#endif
  free( peer_list );
}

static void vector_remove_torrent( ot_vector *vector, ot_torrent *match ) {
  ot_torrent *end = ((ot_torrent*)vector->data) + vector->size;

  if( !vector->size ) return;

  /* If this is being called after a unsuccessful malloc() for peer_list
     in add_peer_to_torrent, match->peer_list actually might be NULL */
  if( match->peer_list) free_peerlist( match->peer_list );

  memmove( match, match + 1, sizeof(ot_torrent) * ( end - match - 1 ) );
  if( ( --vector->size * OT_VECTOR_SHRINK_THRESH < vector->space ) && ( vector->space > OT_VECTOR_MIN_MEMBERS ) ) {
    vector->space /= OT_VECTOR_SHRINK_RATIO;
    vector->data = realloc( vector->data, vector->space * sizeof( ot_torrent ) );
  }
}

ot_torrent *add_peer_to_torrent( ot_hash *hash, ot_peer *peer  WANT_TRACKER_SYNC_PARAM( int from_changeset ) ) {
  int         exactmatch;
  ot_torrent *torrent;
  ot_peer    *peer_dest;
  ot_vector  *torrents_list = lock_bucket_by_hash( hash ), *peer_pool;
  int         base_pool = 0;

#ifdef WANT_ACCESS_CONTROL
  binary_search( hash, accesslist.data, accesslist.size, OT_HASH_COMPARE_SIZE, OT_HASH_COMPARE_SIZE, &exactmatch );

#ifdef WANT_CLOSED_TRACKER
  exactmatch = !exactmatch;
#endif

  if( exactmatch )
    return unlock_bucket_by_hash( hash );
#endif

  torrent = vector_find_or_insert( torrents_list, (void*)hash, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  if( !torrent )
    return unlock_bucket_by_hash( hash );

  if( !exactmatch ) {
    /* Create a new torrent entry, then */
    memmove( &torrent->hash, hash, sizeof( ot_hash ) );

    if( !( torrent->peer_list = malloc( sizeof (ot_peerlist) ) ) ) {
      vector_remove_torrent( torrents_list, torrent );
      return unlock_bucket_by_hash( hash );
    }

    byte_zero( torrent->peer_list, sizeof( ot_peerlist ) );
    torrent->peer_list->base = NOW;
  } else
    clean_single_torrent( torrent );

  /* Sanitize flags: Whoever claims to have completed download, must be a seeder */
  if( ( OT_FLAG( peer ) & ( PEER_FLAG_COMPLETED | PEER_FLAG_SEEDING ) ) == PEER_FLAG_COMPLETED )
    OT_FLAG( peer ) ^= PEER_FLAG_COMPLETED;

#ifdef WANT_TRACKER_SYNC
  if( from_changeset ) {
    /* Check, whether peer already is in current pool, do nothing if so */
    peer_pool = &torrent->peer_list->peers[0];
    binary_search( peer, peer_pool->data, peer_pool->size, sizeof(ot_peer), OT_PEER_COMPARE_SIZE, &exactmatch );
    if( exactmatch ) {
      unlock_bucket_by_hash( hash );
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
                unlock_bucket_by_hash( hash );
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

  unlock_bucket_by_hash( hash );
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
  ot_vector   *torrents_list = lock_bucket_by_hash( hash );
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  ot_peerlist *peer_list = torrent->peer_list;
  size_t       index;

  if( !torrent ) {
    unlock_bucket_by_hash( hash );
    return 0;
  }

  if( peer_list->peer_count < amount )
    amount = peer_list->peer_count;

  if( is_tcp )
    r += sprintf( r, "d8:completei%zde10:incompletei%zde8:intervali%ie5:peers%zd:", peer_list->seed_count, peer_list->peer_count-peer_list->seed_count, OT_CLIENT_REQUEST_INTERVAL_RANDOM, 6*amount );
  else {
    *(ot_dword*)(r+0) = htonl( OT_CLIENT_REQUEST_INTERVAL_RANDOM );
    *(ot_dword*)(r+4) = htonl( peer_list->peer_count );
    *(ot_dword*)(r+8) = htonl( peer_list->seed_count );
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

  unlock_bucket_by_hash( hash );
  return r - reply;
}

/* Release memory we allocated too much */
static void fix_mmapallocation( void *buf, size_t old_alloc, size_t new_alloc ) {
  int page_size = getpagesize();
  size_t old_pages = 1 + old_alloc / page_size;
  size_t new_pages = 1 + new_alloc / page_size;

  if( old_pages != new_pages )
    munmap( ((char*)buf) +  new_pages * page_size, old_alloc - new_pages * page_size );
}

/* Fetch full scrape info for all torrents */
size_t return_fullscrape_for_tracker( char **reply ) {
  size_t torrent_count = 0, j;
  size_t allocated, replysize;
  int    i;
  char  *r;

  for( i=0; i<OT_BUCKET_COUNT; ++i )
    torrent_count += all_torrents[i].size;

  /* one extra for pro- and epilogue */
  allocated = 100*(1+torrent_count);
  if( !( r = *reply = mmap( NULL, allocated, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0 ) ) ) return 0;

  memmove( r, "d5:filesd", 9 ); r += 9;
  for( i=0; i<OT_BUCKET_COUNT; ++i ) {
    ot_vector *torrents_list = all_torrents + i;
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      ot_hash     *hash      =&( ((ot_torrent*)(torrents_list->data))[j] ).hash;
      if( peer_list->peer_count || peer_list->down_count ) {
        *r++='2'; *r++='0'; *r++=':';
        memmove( r, hash, 20 ); r+=20;
        r += sprintf( r, "d8:completei%zde10:downloadedi%zde10:incompletei%zdee", peer_list->seed_count, peer_list->down_count, peer_list->peer_count-peer_list->seed_count );
      }
    }
  }

  *r++='e'; *r++='e';

  replysize = ( r - *reply );
  fix_mmapallocation( *reply, allocated, replysize );

  return replysize;
}

size_t return_memstat_for_tracker( char **reply ) {
  size_t torrent_count = 0, j;
  size_t allocated, replysize;
  int    i, k;
  char  *r;

  for( i=0; i<OT_BUCKET_COUNT; ++i ) {
    ot_vector *torrents_list = all_torrents + i;
    torrent_count += torrents_list->size;
  }

  allocated = OT_BUCKET_COUNT*32 + (43+OT_POOLS_COUNT*32)*torrent_count;
  if( !( r = *reply = mmap( NULL, allocated, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0 ) ) ) return 0;

  for( i=0; i<OT_BUCKET_COUNT; ++i )
    r += sprintf( r, "%02X: %08X %08X\n", i, (unsigned int)all_torrents[i].size, (unsigned int)all_torrents[i].space );

  for( i=0; i<OT_BUCKET_COUNT; ++i ) {
    ot_vector *torrents_list = all_torrents + i;
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      ot_hash     *hash      =&( ((ot_torrent*)(torrents_list->data))[j] ).hash;
      r += sprintf( r, "\n%s:\n", to_hex( (ot_byte*)hash ) );
      for( k=0; k<OT_POOLS_COUNT; ++k )
        r += sprintf( r, "\t%05X %05X\n", ((unsigned int)peer_list->peers[k].size), (unsigned int)peer_list->peers[k].space );
    }
  }

  replysize = ( r - *reply );
  fix_mmapallocation( *reply, allocated, replysize );

  return replysize;
}

/* Fetches scrape info for a specific torrent */
size_t return_udp_scrape_for_torrent( ot_hash *hash, char *reply ) {
  int          exactmatch;
  ot_vector   *torrents_list = lock_bucket_by_hash( hash );
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );

  if( !exactmatch ) {
    memset( reply, 0, 12);
  } else {
    ot_dword *r = (ot_dword*) reply;

    if( clean_single_torrent( torrent ) ) {
      vector_remove_torrent( torrents_list, torrent );
      memset( reply, 0, 12);
    } else {
      r[0] = htonl( torrent->peer_list->seed_count );
      r[1] = htonl( torrent->peer_list->down_count );
      r[2] = htonl( torrent->peer_list->peer_count-torrent->peer_list->seed_count );
    }
  }
  unlock_bucket_by_hash( hash );
  return 12;
}

/* Fetches scrape info for a specific torrent */
size_t return_tcp_scrape_for_torrent( ot_hash *hash_list, int amount, char *reply ) {
  char        *r = reply;
  int          exactmatch, i;

  r += sprintf( r, "d5:filesd" );

  for( i=0; i<amount; ++i ) {
    ot_hash     *hash = hash_list + i;
    ot_vector   *torrents_list = lock_bucket_by_hash( hash );
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
    unlock_bucket_by_hash( hash );
  }

  *r++ = 'e'; *r++ = 'e';
  return r - reply;
}

#ifdef WANT_TRACKER_SYNC
/* Import Changeset from an external authority
   format: d4:syncd[..]ee
   [..]:   ( 20:01234567890abcdefghij16:XXXXYYYY )+
*/
int add_changeset_to_tracker( ot_byte *data, size_t len ) {
  ot_hash    *hash;
  ot_byte    *end = data + len;
  unsigned long      peer_count;

  /* We do know, that the string is \n terminated, so it cant
     overflow */
  if( byte_diff( data, 8, "d4:syncd" ) ) return -1;
  data += 8;

  while( 1 ) {
    if( byte_diff( data, 3, "20:" ) ) {
      if( byte_diff( data, 2, "ee" ) )
        return -1;
      return 0;
    }
    data += 3;
    hash = (ot_hash*)data;
    data += sizeof( ot_hash );

    /* Scan string length indicator */
    data += ( len = scan_ulong( (char*)data, &peer_count ) );

    /* If no long was scanned, it is not divisible by 8, it is not
       followed by a colon or claims to need to much memory, we fail */
    if( !len || !peer_count || ( peer_count & 7 ) || ( *data++ != ':' ) || ( data + peer_count > end ) )
      return -1;

    while( peer_count > 0 ) {
      add_peer_to_torrent( hash, (ot_peer*)data, 1 );
      data += 8; peer_count -= 8;
    }
  }
  return 0;
}

/* Proposed output format
   d4:syncd20:<info_hash>8*N:(xxxxyyyy)*Nee
*/
size_t return_changeset_for_tracker( char **reply ) {
  size_t allocated = 0, i, replysize;
  int    bucket;
  char   *r;

  /* Maybe there is time to clean_all_torrents(); */

  /* Determine space needed for whole changeset */
  for( bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = all_torrents + bucket;
    for( i=0; i<torrents_list->size; ++i ) {
      ot_torrent *torrent = ((ot_torrent*)(torrents_list->data)) + i;
      allocated += sizeof( ot_hash ) + sizeof(ot_peer) * torrent->peer_list->changeset.size + 13;
    }
  }

  /* add "d4:syncd" and "ee" */
  allocated += 8 + 2;

  if( !( r = *reply = mmap( NULL, allocated, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0 ) ) )
    return 0;

  memmove( r, "d4:syncd", 8 ); r += 8;
  for( bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = all_torrents + bucket;
    for( i=0; i<torrents_list->size; ++i ) {
      ot_torrent *torrent = ((ot_torrent*)(torrents_list->data)) + i;
      const size_t byte_count = sizeof(ot_peer) * torrent->peer_list->changeset.size;
      *r++ = '2'; *r++ = '0'; *r++ = ':';
      memmove( r, torrent->hash, sizeof( ot_hash ) ); r += sizeof( ot_hash );
      r += sprintf( r, "%zd:", byte_count );
      memmove( r, torrent->peer_list->changeset.data, byte_count ); r += byte_count;
    }
  }
  *r++ = 'e'; *r++ = 'e';

  replysize = ( r - *reply );
  fix_mmapallocation( *reply, allocated, replysize );

  return replysize;
}
#endif

/* Clean a single torrent
   return 1 if torrent timed out
*/
static int clean_single_torrent( ot_torrent *torrent ) {
  ot_peerlist *peer_list = torrent->peer_list;
  size_t peers_count = 0, seeds_count;
  time_t timedout = (int)( NOW - peer_list->base );
  int i;
#ifdef WANT_TRACKER_SYNC
  char *new_peers;
#endif

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

/* Clean up all peers in current bucket, remove timedout pools and
   torrents */
void clean_all_torrents( void ) {
  ot_vector         *torrents_list;
  size_t             i;
  static int         bucket;
  ot_time time_now = NOW;

  /* Search for an uncleaned bucked */
  while( ( all_torrents_clean[bucket] == time_now ) && ( ++bucket < OT_BUCKET_COUNT ) );
  if( bucket >= OT_BUCKET_COUNT ) {
    bucket = 0; return;
  }

  all_torrents_clean[bucket] = time_now;

  torrents_list = all_torrents + bucket;
  for( i=0; i<torrents_list->size; ++i ) {
    ot_torrent *torrent = ((ot_torrent*)(torrents_list->data)) + i;
    if( clean_single_torrent( torrent ) ) {
      vector_remove_torrent( torrents_list, torrent );
      --i; continue;
    }
  }
}

typedef struct { size_t val; ot_torrent * torrent; } ot_record;

/* Fetches stats from tracker */
size_t return_stats_for_tracker( char *reply, int mode ) {
  size_t    torrent_count = 0, peer_count = 0, seed_count = 0, j;
  ot_record top5s[5], top5c[5];
  char     *r  = reply;
  int       i;

  byte_zero( top5s, sizeof( top5s ) );
  byte_zero( top5c, sizeof( top5c ) );

  for( i=0; i<OT_BUCKET_COUNT; ++i ) {
    ot_vector *torrents_list = all_torrents + i;
    torrent_count += torrents_list->size;
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      if( mode == STATS_TOP5 ) {
        int idx = 4; while( (idx >= 0) && ( peer_list->peer_count > top5c[idx].val ) ) --idx;
        if ( idx++ != 4 ) {
          memmove( top5c + idx + 1, top5c + idx, ( 4 - idx ) * sizeof( ot_record ) );
          top5c[idx].val = peer_list->peer_count;
          top5c[idx].torrent = (ot_torrent*)(torrents_list->data) + j;
        }
        idx = 4; while( (idx >= 0) && ( peer_list->seed_count > top5s[idx].val ) ) --idx;
        if ( idx++ != 4 ) {
          memmove( top5s + idx + 1, top5s + idx, ( 4 - idx ) * sizeof( ot_record ) );
          top5s[idx].val = peer_list->seed_count;
          top5s[idx].torrent = (ot_torrent*)(torrents_list->data) + j;
        }
      }
      peer_count += peer_list->peer_count; seed_count += peer_list->seed_count;
    }
  }
  if( mode == STATS_TOP5 ) {
    int idx;
    r += sprintf( r, "Top5 torrents by peers:\n" );
    for( idx=0; idx<5; ++idx )
      if( top5c[idx].torrent )
        r += sprintf( r, "\t%zd\t%s\n", top5c[idx].val, to_hex(top5c[idx].torrent->hash) );
    r += sprintf( r, "Top5 torrents by seeds:\n" );
    for( idx=0; idx<5; ++idx )
      if( top5s[idx].torrent )
        r += sprintf( r, "\t%zd\t%s\n", top5s[idx].val, to_hex(top5s[idx].torrent->hash) );
  } else {
    r += sprintf( r, "%zd\n%zd\nopentracker serving %zd torrents\nopentracker", peer_count, seed_count, torrent_count );
  }

  return r - reply;
}

/* This function collects 4096 /24s in 4096 possible
   malloc blocks
*/
size_t return_stats_for_slash24s( char *reply, size_t amount, ot_dword thresh ) {

#define NUM_TOPBITS 12
#define NUM_LOWBITS (24-NUM_TOPBITS)
#define NUM_BUFS    (1<<NUM_TOPBITS)
#define NUM_S24S    (1<<NUM_LOWBITS)
#define MSK_S24S    (NUM_S24S-1)

  ot_dword *counts[ NUM_BUFS ];
  ot_dword slash24s[amount*2];  /* first dword amount, second dword subnet */
  size_t i, j, k, l;
  char     *r  = reply;

  byte_zero( counts, sizeof( counts ) );
  byte_zero( slash24s, amount * 2 * sizeof(ot_dword) );

  r += sprintf( r, "Stats for all /24s with more than %u announced torrents:\n\n", thresh );

  for( i=0; i<OT_BUCKET_COUNT; ++i ) {
    ot_vector *torrents_list = all_torrents + i;
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      for( k=0; k<OT_POOLS_COUNT; ++k ) {
        ot_peer *peers =    peer_list->peers[k].data;
        size_t   numpeers = peer_list->peers[k].size;
        for( l=0; l<numpeers; ++l ) {
          ot_dword s24 = ntohl(*(ot_dword*)(peers+l)) >> 8;
          ot_dword *count = counts[ s24 >> NUM_LOWBITS ];
          if( !count ) {
            count = malloc( sizeof(ot_dword) * NUM_S24S );
            if( !count )
              goto bailout_cleanup;
            byte_zero( count, sizeof( ot_dword ) * NUM_S24S );
            counts[ s24 >> NUM_LOWBITS ] = count;
          }
          count[ s24 & MSK_S24S ]++;
        }
      }
    }
  }

  k = l = 0; /* Debug: count allocated bufs */
  for( i=0; i < NUM_BUFS; ++i ) {
    ot_dword *count = counts[i];
    if( !counts[i] )
      continue;
    ++k; /* Debug: count allocated bufs */
    for( j=0; j < NUM_S24S; ++j ) {
      if( count[j] > thresh ) {
        /* This subnet seems to announce more torrents than the last in our list */
        int insert_pos = amount - 1;
        while( ( insert_pos >= 0 ) && ( count[j] > slash24s[ 2 * insert_pos ] ) )
          --insert_pos;
        ++insert_pos;
        memmove( slash24s + 2 * ( insert_pos + 1 ), slash24s + 2 * ( insert_pos ), 2 * sizeof( ot_dword ) * ( amount - insert_pos - 1 ) );
        slash24s[ 2 * insert_pos     ] = count[j];
        slash24s[ 2 * insert_pos + 1 ] = ( i << NUM_TOPBITS ) + j;
        if( slash24s[ 2 * amount - 2 ] > thresh )
          thresh = slash24s[ 2 * amount - 2 ];
      }
      if( count[j] ) ++l;
    }
    free( count );
  }

  r += sprintf( r, "Allocated bufs: %zd, used s24s: %zd\n", k, l );

  for( i=0; i < amount; ++i )
    if( slash24s[ 2*i ] >= thresh ) {
      ot_dword ip = slash24s[ 2*i +1 ];
      r += sprintf( r, "% 10ld %d.%d.%d.0/24\n", (long)slash24s[ 2*i ], (int)(ip >> 16), (int)(255 & ( ip >> 8 )), (int)(ip & 255) );
    }

  return r - reply;

bailout_cleanup:

  for( i=0; i < NUM_BUFS; ++i )
    free( counts[i] );

  return 0;
}

size_t return_stats_for_slash24s_old( char *reply, size_t amount, ot_dword thresh ) {
  ot_word *count = malloc( 0x1000000 * sizeof(ot_word) );
  ot_dword slash24s[amount*2];  /* first dword amount, second dword subnet */
  size_t i, j, k, l;
  char     *r  = reply;

  if( !count )
    return 0;

  byte_zero( count, 0x1000000 * sizeof(ot_word) );
  byte_zero( slash24s, amount * 2 * sizeof(ot_dword) );

  r += sprintf( r, "Stats for all /24s with more than %d announced torrents:\n\n", ((int)thresh) );

  for( i=0; i<OT_BUCKET_COUNT; ++i ) {
    ot_vector *torrents_list = all_torrents + i;
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      for( k=0; k<OT_POOLS_COUNT; ++k ) {
        ot_peer *peers =    peer_list->peers[k].data;
        size_t   numpeers = peer_list->peers[k].size;
        for( l=0; l<numpeers; ++l )
          if( ++count[ ntohl(*(ot_dword*)(peers+l))>>8 ] == 65335 )
            count[ ntohl(*(ot_dword*)(peers+l))>>8 ] = 65334;
      }
    }
  }

  for( i=0; i<0x1000000; ++i )
    if( count[i] > thresh ) {
      /* This subnet seems to announce more torrents than the last in our list */
      int insert_pos = amount - 1;
      while( ( insert_pos >= 0 ) && ( count[i] > slash24s[ 2 * insert_pos ] ) )
        --insert_pos;
      ++insert_pos;
      memmove( slash24s + 2 * ( insert_pos + 1 ), slash24s + 2 * ( insert_pos ), 2 * sizeof( ot_dword ) * ( amount - insert_pos - 1 ) );
      slash24s[ 2 * insert_pos     ] = count[i];
      slash24s[ 2 * insert_pos + 1 ] = i;
      if( slash24s[ 2 * amount - 2 ] > thresh )
        thresh = slash24s[ 2 * amount - 2 ];
    }

  free( count );

  for( i=0; i < amount; ++i )
    if( slash24s[ 2*i ] >= thresh ) {
      unsigned long ip = slash24s[ 2*i +1 ];
      r += sprintf( r, "% 10ld %d.%d.%d.0/24\n", (long)slash24s[ 2*i ], (int)(ip >> 16), (int)(255 & ( ip >> 8 )), (int)(ip & 255) );
    }

  return r - reply;
}

size_t remove_peer_from_torrent( ot_hash *hash, ot_peer *peer, char *reply, int is_tcp ) {
  int          exactmatch;
  size_t       index;
  ot_vector   *torrents_list = lock_bucket_by_hash( hash );
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  ot_peerlist *peer_list;

  if( !exactmatch ) {
    unlock_bucket_by_hash( hash );

    if( is_tcp )
      return sprintf( reply, "d8:completei0e10:incompletei0e8:intervali%ie5:peers0:e", OT_CLIENT_REQUEST_INTERVAL_RANDOM );

    /* Create fake packet to satisfy parser on the other end */
    ((ot_dword*)reply)[2] = htonl( OT_CLIENT_REQUEST_INTERVAL_RANDOM );
    ((ot_dword*)reply)[3] = ((ot_dword*)reply)[4] = 0;
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
    unlock_bucket_by_hash( hash );
    return reply_size;
  }

  /* else { Handle UDP reply */
  ((ot_dword*)reply)[2] = htonl( OT_CLIENT_REQUEST_INTERVAL_RANDOM );
  ((ot_dword*)reply)[3] = peer_list->peer_count - peer_list->seed_count;
  ((ot_dword*)reply)[4] = peer_list->seed_count;

  unlock_bucket_by_hash( hash );
  return (size_t)20;
}

int trackerlogic_init( const char * const serverdir ) {
  if( serverdir && chdir( serverdir ) ) {
    fprintf( stderr, "Could not chdir() to %s\n", serverdir );
    return -1;
  }

  srandom( time(NULL) );

  /* Initialize control structures */
  byte_zero( all_torrents, sizeof( all_torrents ) );

  mutex_init( );

  return 0;
}

void trackerlogic_deinit( void ) {
  int i;
  size_t j;

  /* Free all torrents... */
  for(i=0; i<OT_BUCKET_COUNT; ++i ) {
    if( all_torrents[i].size ) {
      ot_torrent *torrents_list = (ot_torrent*)all_torrents[i].data;
      for( j=0; j<all_torrents[i].size; ++j )
        free_peerlist( torrents_list[j].peer_list );
      free( all_torrents[i].data );
    }
  }
  byte_zero( all_torrents, sizeof (all_torrents));
  byte_zero( all_torrents_clean, sizeof (all_torrents_clean));

  mutex_deinit( );
}

#ifdef WANT_ACCESS_CONTROL
void accesslist_reset( void ) {
  free( accesslist.data );
  byte_zero( &accesslist, sizeof( accesslist ) );
}

int accesslist_addentry( ot_hash *infohash ) {
  int em;
  void *insert = vector_find_or_insert( &accesslist, infohash, OT_HASH_COMPARE_SIZE, OT_HASH_COMPARE_SIZE, &em );

  if( !insert )
    return -1;

  memmove( insert, infohash, OT_HASH_COMPARE_SIZE );

  return 0;
}
#endif
