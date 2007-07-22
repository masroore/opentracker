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

/* GLOBAL VARIABLES */
static ot_vector all_torrents[256];
static ot_vector changeset;
#ifdef WANT_BLACKLISTING
static ot_vector blacklist;
#endif

size_t changeset_size = 0;
time_t last_clean_time = 0;

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
  free( peer_list );
}

/* This is the non-generic delete from vector-operation specialized for torrents in buckets.
   it returns 0 if the hash wasn't found in vector
              1 if the torrent was removed from vector
*/
static int vector_remove_torrent( ot_vector *vector, ot_hash *hash ) {
  int exactmatch;
  ot_torrent *end = ((ot_torrent*)vector->data) + vector->size;
  ot_torrent *match;

  if( !vector->size ) return 0;

  match = binary_search( hash, vector->data, vector->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  if( !exactmatch ) return 0;

  /* If this is being called after a unsuccessful malloc() for peer_list
     in add_peer_to_torrent, match->peer_list actually might be NULL */
  if( match->peer_list) free_peerlist( match->peer_list );

  memmove( match, match + 1, sizeof(ot_torrent) * ( end - match - 1 ) );
  if( ( --vector->size * OT_VECTOR_SHRINK_THRESH < vector->space ) && ( vector->space > OT_VECTOR_MIN_MEMBERS ) ) {
    vector->space /= OT_VECTOR_SHRINK_RATIO;
    vector->data = realloc( vector->data, vector->space * sizeof( ot_torrent ) );
  }
  return 1;
}

ot_torrent *add_peer_to_torrent( ot_hash *hash, ot_peer *peer, int from_changeset ) {
  int         exactmatch;
  ot_torrent *torrent;
  ot_peer    *peer_dest;
  ot_vector  *torrents_list = &all_torrents[*hash[0]], *peer_pool;
  int         base_pool = 0;

#ifdef WANT_BLACKLISTING
  binary_search( hash, blacklist.data, blacklist.size, OT_HASH_COMPARE_SIZE, OT_HASH_COMPARE_SIZE, &exactmatch );
  if( exactmatch )
    return NULL;
#endif

  torrent = vector_find_or_insert( torrents_list, (void*)hash, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  if( !torrent ) return NULL;

  if( !exactmatch ) {
    /* Create a new torrent entry, then */
    memmove( &torrent->hash, hash, sizeof( ot_hash ) );

    if( !( torrent->peer_list = malloc( sizeof (ot_peerlist) ) ) ) {
      vector_remove_torrent( torrents_list, hash );
      return NULL;
    }

    byte_zero( torrent->peer_list, sizeof( ot_peerlist ) );
    torrent->peer_list->base = NOW;
  }

  /* Sanitize flags: Whoever claims to have completed download, must be a seeder */
  if( ( OT_FLAG( peer ) & ( PEER_FLAG_COMPLETED | PEER_FLAG_SEEDING ) ) == PEER_FLAG_COMPLETED )
    OT_FLAG( peer ) ^= PEER_FLAG_COMPLETED;

  if( from_changeset ) {
    /* Check, whether peer already is in current pool, do nothing if so */
    peer_pool = &torrent->peer_list->peers[0];
    binary_search( peer, peer_pool->data, peer_pool->size, sizeof(ot_peer), OT_PEER_COMPARE_SIZE, &exactmatch );
    if( exactmatch )
      return torrent;
    base_pool = 1;
  }

  peer_pool = &torrent->peer_list->peers[ base_pool ];
  peer_dest = vector_find_or_insert( peer_pool, (void*)peer, sizeof( ot_peer ), OT_PEER_COMPARE_SIZE, &exactmatch );

  /* If we hadn't had a match in current pool, create peer there and
     remove it from all older pools */
  if( !exactmatch ) {
    int i;
    memmove( peer_dest, peer, sizeof( ot_peer ) );

    if( OT_FLAG( peer ) & PEER_FLAG_COMPLETED )
      torrent->peer_list->downloaded++;

    if( OT_FLAG(peer) & PEER_FLAG_SEEDING )
      torrent->peer_list->seed_count[ base_pool ]++;

    for( i= base_pool + 1; i<OT_POOLS_COUNT; ++i ) {
      switch( vector_remove_peer( &torrent->peer_list->peers[i], peer, 0 ) ) {
        case 0: continue;
        case 2: torrent->peer_list->seed_count[i]--;
        case 1: default: return torrent;
      }
    }
  } else {
    if( (OT_FLAG(peer_dest) & PEER_FLAG_SEEDING ) && !(OT_FLAG(peer) & PEER_FLAG_SEEDING ) )
      torrent->peer_list->seed_count[ base_pool ]--;
    if( !(OT_FLAG(peer_dest) & PEER_FLAG_SEEDING ) && (OT_FLAG(peer) & PEER_FLAG_SEEDING ) )
      torrent->peer_list->seed_count[ base_pool ]++;
    if( !(OT_FLAG( peer_dest ) & PEER_FLAG_COMPLETED ) && (OT_FLAG( peer ) & PEER_FLAG_COMPLETED ) )
      torrent->peer_list->downloaded++;
    if( OT_FLAG( peer_dest ) & PEER_FLAG_COMPLETED )
      OT_FLAG( peer ) |= PEER_FLAG_COMPLETED;

    memmove( peer_dest, peer, sizeof( ot_peer ) );
  }

  return torrent;
}

/* Compiles a list of random peers for a torrent
   * reply must have enough space to hold 92+6*amount bytes
   * Selector function can be anything, maybe test for seeds, etc.
   * RANDOM may return huge values
   * does not yet check not to return self
*/
size_t return_peers_for_torrent( ot_torrent *torrent, size_t amount, char *reply, int is_tcp ) {
  char  *r = reply;
  size_t peer_count, seed_count, index;

  for( peer_count = seed_count = index = 0; index < OT_POOLS_COUNT; ++index ) {
    peer_count += torrent->peer_list->peers[index].size;
    seed_count += torrent->peer_list->seed_count[index];
  }

  if( peer_count < amount )
    amount = peer_count;

  if( is_tcp )
    r += sprintf( r, "d8:completei%zde10:incompletei%zde8:intervali%ie5:peers%zd:", seed_count, peer_count-seed_count, OT_CLIENT_REQUEST_INTERVAL_RANDOM, 6*amount );
  else {
    *(ot_dword*)(r+0) = htonl( OT_CLIENT_REQUEST_INTERVAL_RANDOM );
    *(ot_dword*)(r+4) = htonl( peer_count );
    *(ot_dword*)(r+8) = htonl( seed_count );
    r += 12;
  }

  if( amount ) {
    unsigned int pool_offset, pool_index = 0;;
    unsigned int shifted_pc = peer_count;
    unsigned int shifted_step = 0;
    unsigned int shift = 0;

    /* Make fixpoint arithmetic as exact as possible */
#define MAXPRECBIT (1<<(8*sizeof(int)-3))
    while( !(shifted_pc & MAXPRECBIT ) ) { shifted_pc <<= 1; shift++; }
    shifted_step = shifted_pc/amount;
#undef MAXPRECBIT

    /* Initialize somewhere in the middle of peers so that
       fixpoint's aliasing doesn't alway miss the same peers */
    pool_offset = random() % peer_count;

    for( index = 0; index < amount; ++index ) {
      /* This is the aliased, non shifted range, next value may fall into */
      unsigned int diff = ( ( ( index + 1 ) * shifted_step ) >> shift ) -
                          ( (   index       * shifted_step ) >> shift );
      pool_offset += 1 + random() % diff;

      while( pool_offset >= torrent->peer_list->peers[pool_index].size ) {
        pool_offset -= torrent->peer_list->peers[pool_index].size;
        pool_index = ( pool_index + 1 ) % OT_POOLS_COUNT;
      }

      memmove( r, ((ot_peer*)torrent->peer_list->peers[pool_index].data) + pool_offset, 6 );
      r += 6;
    }
  }
  if( is_tcp )
    *r++ = 'e';

  return r - reply;
}

/* Fetch full scrape info for all torrents */
size_t return_fullscrape_for_tracker( char **reply ) {
  size_t torrent_count = 0, j;
  int    i, k;
  char  *r;

  for( i=0; i<256; ++i )
    torrent_count += all_torrents[i].size;

  if( !( r = *reply = malloc( 128*torrent_count ) ) ) return 0;

  memmove( r, "d5:filesd", 9 ); r += 9;
  for( i=0; i<256; ++i ) {
    ot_vector *torrents_list = &all_torrents[i];
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      ot_hash     *hash      =&( ((ot_torrent*)(torrents_list->data))[j] ).hash;
      size_t       peers = 0, seeds = 0;
      for( k=0; k<OT_POOLS_COUNT; ++k ) {
        peers += peer_list->peers[k].size;
        seeds += peer_list->seed_count[k];
      }
      *r++='2'; *r++='0'; *r++=':';
      memmove( r, hash, 20 ); r+=20;
      r += sprintf( r, "d8:completei%zde10:downloadedi%zde10:incompletei%zdee", seeds, peer_list->downloaded, peers-seeds );
    }
  }

  *r++='e'; *r++='e';
  return r - *reply;
}

size_t return_memstat_for_tracker( char **reply ) {
  size_t torrent_count = 0, j;
  int    i, k;
  char  *r;

  for( i=0; i<256; ++i ) {
    ot_vector *torrents_list = &all_torrents[i];
    torrent_count += torrents_list->size;
  }

  if( !( r = *reply = malloc( 256*32 + (43+OT_POOLS_COUNT*32)*torrent_count ) ) ) return 0;

  for( i=0; i<256; ++i )
    r += sprintf( r, "%02X: %08X %08X\n", i, (unsigned int)all_torrents[i].size, (unsigned int)all_torrents[i].space );

  for( i=0; i<256; ++i ) {
    ot_vector *torrents_list = &all_torrents[i];
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      ot_hash     *hash      =&( ((ot_torrent*)(torrents_list->data))[j] ).hash;
      r += sprintf( r, "\n%s:\n", to_hex( (ot_byte*)hash ) );
      for( k=0; k<OT_POOLS_COUNT; ++k )
        r += sprintf( r, "\t%05X %05X\n", ((unsigned int)peer_list->peers[k].size), (unsigned int)peer_list->peers[k].space );
    }
  }

  return r - *reply;
}

/* Fetches scrape info for a specific torrent */
size_t return_udp_scrape_for_torrent( ot_hash *hash, char *reply ) {
  int          exactmatch, i;
  size_t       peers = 0, seeds = 0;
  ot_vector   *torrents_list = &all_torrents[*hash[0]];
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );

  if( !exactmatch ) {
    memset( reply, 0, 12);
  } else {
    ot_dword *r = (ot_dword*) reply;

    for( i=0; i<OT_POOLS_COUNT; ++i ) {
      peers += torrent->peer_list->peers[i].size;
      seeds += torrent->peer_list->seed_count[i];
    }
    r[0] = htonl( seeds );
    r[1] = htonl( torrent->peer_list->downloaded );
    r[2] = htonl( peers-seeds );
  }
  return 12;
}

/* Fetches scrape info for a specific torrent */
size_t return_tcp_scrape_for_torrent( ot_hash *hash, char *reply ) {
  char        *r = reply;
  int          exactmatch, i;
  size_t       peers = 0, seeds = 0;
  ot_vector   *torrents_list = &all_torrents[*hash[0]];
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );

  if( !exactmatch ) return sprintf( r, "d5:filesdee" );

  for( i=0; i<OT_POOLS_COUNT; ++i ) {
    peers += torrent->peer_list->peers[i].size;
    seeds += torrent->peer_list->seed_count[i];
  }

  memmove( r, "d5:filesd20:", 12 ); memmove( r+12, hash, 20 );
  r += sprintf( r+32, "d8:completei%zde10:downloadedi%zde10:incompletei%zdeeee", seeds, torrent->peer_list->downloaded, peers-seeds ) + 32;

  return r - reply;
}

/* Throw away old changeset */
static void release_changeset( void ) {
  ot_byte **changeset_ptrs = (ot_byte**)(changeset.data);
  size_t i;

  for( i = 0; i < changeset.size; ++i )
    free( changeset_ptrs[i] );

  free( changeset_ptrs );
  byte_zero( &changeset, sizeof( changeset ) );

  changeset_size = 0;
}

static void add_pool_to_changeset( ot_hash *hash, ot_peer *peers, size_t peer_count ) {
  ot_byte *pool_copy = (ot_byte *)malloc( sizeof( size_t ) + sizeof( ot_hash ) + sizeof( ot_peer ) * peer_count + 13 );
  size_t r = 0;

  if( !pool_copy )
    return;

  memmove( pool_copy + sizeof( size_t ), "20:", 3 );
  memmove( pool_copy + sizeof( size_t ) + 3, hash, sizeof( ot_hash ) );
  r = sizeof( size_t ) + 3 + sizeof( ot_hash );
  r += sprintf( (char*)pool_copy + r, "%zd:", sizeof( ot_peer ) * peer_count );
  memmove( pool_copy + r, peers, sizeof( ot_peer ) * peer_count );
  r += sizeof( ot_peer ) * peer_count;

  /* Without the length field */
  *(size_t*)pool_copy = r - sizeof( size_t );

  if( changeset.size + 1 >= changeset.space ) {
    size_t   new_space = changeset.space ? OT_VECTOR_GROW_RATIO * changeset.space : OT_VECTOR_MIN_MEMBERS;
    ot_byte *new_data = realloc( changeset.data, new_space * sizeof( ot_byte *) );

    if( !new_data )
      return free( pool_copy );

    changeset.data = new_data;
    changeset.space = new_space;
  }

  ((ot_byte**)changeset.data)[changeset.size++] = pool_copy;

  /* Without the length field */
  changeset_size += r - sizeof( size_t );
}

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
  size_t i, r = 8;

  clean_all_torrents();

  *reply = malloc( 8 + changeset_size + 2 );
  if( !*reply )
    return 0;

  memmove( *reply, "d4:syncd", 8 );
  for( i = 0; i < changeset.size; ++i ) {
    ot_byte *data = ((ot_byte**)changeset.data)[i];
    memmove( *reply + r, data + sizeof( size_t ), *(size_t*)data );
    r += *(size_t*)data;
  }

  (*reply)[r++] = 'e';
  (*reply)[r++] = 'e';

  return r;
}

/* Clean up all torrents, remove timedout pools and
   torrents, also prepare new changeset */
void clean_all_torrents( void ) {
  int    i, k;
  size_t j;
  time_t time_now = NOW;
  size_t peers_count;

  if( time_now <= last_clean_time )
    return;
  last_clean_time = time_now;

  release_changeset();

  for( i=0; i<256; ++i ) {
    ot_vector *torrents_list = &all_torrents[i];
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      ot_hash     *hash =&( ((ot_torrent*)(torrents_list->data))[j] ).hash;

      time_t timedout = (int)( time_now - peer_list->base );

      /* Torrent has idled out */
      if( timedout > OT_TORRENT_TIMEOUT ) {
        vector_remove_torrent( torrents_list, hash );
        --j;
      }

      /* If nothing to be cleaned here, handle next torrent */
      if( timedout > OT_POOLS_COUNT )
        continue;

      /* Release vectors that have timed out */
      for( k = OT_POOLS_COUNT - timedout; k < OT_POOLS_COUNT; ++k )
        free( peer_list->peers[k].data);

      /* Shift vectors back by the amount of pools that were shifted out */
      memmove( peer_list->peers + timedout, peer_list->peers, sizeof( ot_vector ) * ( OT_POOLS_COUNT - timedout ) );
      byte_zero( peer_list->peers, sizeof( ot_vector ) * timedout );

      /* Shift back seed counts as well */
      memmove( peer_list->seed_count + timedout, peer_list->seed_count, sizeof( size_t ) * ( OT_POOLS_COUNT - timedout ) );
      byte_zero( peer_list->seed_count, sizeof( size_t ) * timedout );

      /* Save the block modified within last OT_POOLS_TIMEOUT */
      if( peer_list->peers[1].size )
        add_pool_to_changeset( hash, peer_list->peers[1].data, peer_list->peers[1].size );

      peers_count = 0;
      for( k = 0; k < OT_POOLS_COUNT; ++k )
        peers_count += peer_list->peers[k].size;

      if( peers_count ) {
        peer_list->base = time_now;
      } else {
        /* When we got here, the last time that torrent
           has been touched is OT_POOLS_COUNT units before */
        peer_list->base = time_now - OT_POOLS_COUNT;
      }
    }
  }
}

typedef struct { size_t val; ot_torrent * torrent; } ot_record;

/* Fetches stats from tracker */
size_t return_stats_for_tracker( char *reply, int mode ) {
  size_t    torrent_count = 0, peer_count = 0, seed_count = 0, j;
  ot_record top5s[5], top5c[5];
  char     *r  = reply;
  int       i,k;

  byte_zero( top5s, sizeof( top5s ) );
  byte_zero( top5c, sizeof( top5c ) );

  for( i=0; i<256; ++i ) {
    ot_vector *torrents_list = &all_torrents[i];
    torrent_count += torrents_list->size;
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      size_t local_peers = 0, local_seeds = 0;

      for( k=0; k<OT_POOLS_COUNT; ++k ) {
        local_peers += peer_list->peers[k].size;
        local_seeds += peer_list->seed_count[k];
      }
      if( mode == STATS_TOP5 ) {
        int idx = 4; while( (idx >= 0) && ( local_peers > top5c[idx].val ) ) --idx;
        if ( idx++ != 4 ) {
          memmove( top5c + idx + 1, top5c + idx, ( 4 - idx ) * sizeof( ot_record ) );
          top5c[idx].val = local_peers;
          top5c[idx].torrent = (ot_torrent*)(torrents_list->data) + j;
        }
        idx = 4; while( (idx >= 0) && ( local_seeds > top5s[idx].val ) ) --idx;
        if ( idx++ != 4 ) {
          memmove( top5s + idx + 1, top5s + idx, ( 4 - idx ) * sizeof( ot_record ) );
          top5s[idx].val = local_seeds;
          top5s[idx].torrent = (ot_torrent*)(torrents_list->data) + j;
        }
      }
      peer_count += local_peers; seed_count += local_seeds;
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

size_t return_stats_for_slash24s( char *reply, size_t amount, ot_dword thresh ) {
  ot_word *count = malloc( 0x1000000 * sizeof(ot_word) );
  ot_dword slash24s[amount*2];  /* first dword amount, second dword subnet */
  size_t i, j, k, l;
  char     *r  = reply;

  if( !count )
    return 0;

  byte_zero( count, 0x1000000 * sizeof(ot_word) );
  byte_zero( slash24s, amount * 2 * sizeof(ot_dword) );

  r += sprintf( r, "Stats for all /24s with more than %d announced torrents:\n\n", ((int)thresh) );

  for( i=0; i<256; ++i ) {
    ot_vector *torrents_list = &all_torrents[i];
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      for( k=0; k<OT_POOLS_COUNT; ++k ) {
        ot_peer *peers =    peer_list->peers[k].data;
        size_t   numpeers = peer_list->peers[k].size;
        for( l=0; l<numpeers; ++l )
          if( ++count[ (*(ot_dword*)(peers+l))>>8 ] == 65335 )
            count[ (*(ot_dword*)(peers+l))>>8 ] = 65334;
      }
    }
  }

  for( i=0; i<0x1000000; ++i )
    if( count[i] >= thresh ) {
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
      r += sprintf( r, "% 10ld %d.%d.%d/24\n", (long)slash24s[ 2*i ], (int)(ip >> 16), (int)(255 & ( ip >> 8 )), (int)(ip & 255) );
    }

  return r - reply;
}

void remove_peer_from_torrent( ot_hash *hash, ot_peer *peer ) {
  int          exactmatch, i;
  ot_vector   *torrents_list = &all_torrents[*hash[0]];
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );

  if( !exactmatch ) return;

  for( i=0; i<OT_POOLS_COUNT; ++i )
    switch( vector_remove_peer( &torrent->peer_list->peers[i], peer, i == 0 ) ) {
      case 0: continue;
      case 2: torrent->peer_list->seed_count[i]--;
      case 1: default: return;
    }
}

int init_logic( const char * const serverdir ) {
  if( serverdir && chdir( serverdir ) ) {
    fprintf( stderr, "Could not chdir() to %s\n", serverdir );
    return -1;
  }

  srandom( time(NULL) );

  /* Initialize control structures */
  byte_zero( all_torrents, sizeof( all_torrents ) );
  byte_zero( &changeset, sizeof( changeset ) );
  changeset_size = 0;

  return 0;
}

void deinit_logic( void ) {
  int i;
  size_t j;

  /* Free all torrents... */
  for(i=0; i<256; ++i ) {
    if( all_torrents[i].size ) {
      ot_torrent *torrents_list = (ot_torrent*)all_torrents[i].data;
      for( j=0; j<all_torrents[i].size; ++j )
        free_peerlist( torrents_list[j].peer_list );
      free( all_torrents[i].data );
    }
  }
  byte_zero( all_torrents, sizeof (all_torrents));
  byte_zero( &changeset, sizeof( changeset ) );
  changeset_size = 0;
}

#ifdef WANT_BLACKLISTING
void blacklist_reset( void ) {
  free( blacklist.data );
  byte_zero( &blacklist, sizeof( blacklist ) );
}

int blacklist_addentry( ot_hash *infohash ) {
  int em;
  void *insert = vector_find_or_insert( &blacklist, infohash, OT_HASH_COMPARE_SIZE, OT_HASH_COMPARE_SIZE, &em );

  if( !insert )
    return -1;

  memmove( insert, infohash, OT_HASH_COMPARE_SIZE );

  return 0;
}
#endif
