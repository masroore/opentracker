/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include "trackerlogic.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <glob.h>

#include <errno.h>
#include "scan.h"
#include "byte.h"

#if defined( WANT_CLOSED_TRACKER ) || defined( WANT_BLACKLIST )
#include <sys/stat.h>
#endif

/* GLOBAL VARIABLES */
static ot_vector all_torrents[256];

#ifdef WANT_CLOSED_TRACKER
int g_closedtracker = 1;
static ot_torrent* const OT_TORRENT_NOT_ON_WHITELIST = (ot_torrent*)1;
#endif

#ifdef WANT_BLACKLIST
int g_check_blacklist = 1;
static ot_torrent* const OT_TORRENT_ON_BLACKLIST = (ot_torrent*)2;
#endif

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

/* Converter function from memory to human readable hex strings
   - definitely not thread safe!!!
*/
char ths[2+2*20]="-";char*to_hex(ot_byte*s){char*m="0123456789ABCDEF";char*e=ths+41;char*t=ths+1;while(t<e){*t++=m[*s>>4];*t++=m[*s++&15];}*t=0;return ths+1;}

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
	
static int vector_remove_peer( ot_vector *vector, ot_peer *peer ) {
  int exactmatch;
  ot_peer *end = ((ot_peer*)vector->data) + vector->size;
  ot_peer *match;

  if( !vector->size ) return 0;
  match = binary_search( peer, vector->data, vector->size, sizeof( ot_peer ), OT_PEER_COMPARE_SIZE, &exactmatch );

  if( !exactmatch ) return 0;
  exactmatch = ( OT_FLAG( match ) & PEER_FLAG_SEEDING ) ? 2 : 1;
  memmove( match, match + 1, sizeof(ot_peer) * ( end - match - 1 ) );
  if( ( --vector->size * OT_VECTOR_SHRINK_THRESH < vector->space ) && ( vector->space > OT_VECTOR_MIN_MEMBERS ) ) {
    vector->space /= OT_VECTOR_SHRINK_RATIO;
    vector->data = realloc( vector->data, vector->space * sizeof( ot_peer ) );
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

/* Returns 1, if torrent is gone, 0 otherwise
   We expect NOW as a parameter since calling time() may be expensive*/
static int clean_peerlist( time_t time_now, ot_peerlist *peer_list ) {
  int i, timedout = (int)( time_now - peer_list->base );

  if( !timedout ) return 0;
  if( timedout > OT_POOLS_COUNT ) timedout = OT_POOLS_COUNT;

  for( i = OT_POOLS_COUNT - timedout; i < OT_POOLS_COUNT; ++i )
    free( peer_list->peers[i].data);

  memmove( peer_list->peers + timedout, peer_list->peers, sizeof( ot_vector ) * (OT_POOLS_COUNT-timedout) );
  byte_zero( peer_list->peers, sizeof( ot_vector ) * timedout );

  memmove( peer_list->seed_count + timedout, peer_list->seed_count, sizeof( size_t ) * ( OT_POOLS_COUNT - timedout) );
  byte_zero( peer_list->seed_count, sizeof( size_t ) * timedout );

  peer_list->base = NOW;
  return timedout == OT_POOLS_COUNT;
}

ot_torrent *add_peer_to_torrent( ot_hash *hash, ot_peer *peer ) {
  int          exactmatch;
  ot_torrent *torrent;
  ot_peer    *peer_dest;
  ot_vector  *torrents_list = &all_torrents[*hash[0]], *peer_pool;
#if defined( WANT_CLOSED_TRACKER ) || defined( WANT_BLACKLIST )
  struct stat dummy_sb;
  char       *fn = to_hex( (ot_byte*)hash );
#endif

#ifdef WANT_CLOSED_TRACKER
  if( g_closedtracker && stat( fn, &dummy_sb ) )
    return OT_TORRENT_NOT_ON_WHITELIST;
#endif

#ifdef WANT_BLACKLIST
  if( g_check_blacklist && !stat( fn - 1, &dummy_sb ) )
    return OT_TORRENT_ON_BLACKLIST;
#endif

  torrent = vector_find_or_insert( torrents_list, (void*)hash, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  if( !torrent ) return NULL;

  if( !exactmatch ) {
    /* Create a new torrent entry, then */
    memmove( &torrent->hash, hash, sizeof( ot_hash ) );

    torrent->peer_list = malloc( sizeof (ot_peerlist) );
    if( !torrent->peer_list ) {
      vector_remove_torrent( torrents_list, hash );
      return NULL;
    }

    byte_zero( torrent->peer_list, sizeof( ot_peerlist ));
    torrent->peer_list->base = NOW;
  } else
    clean_peerlist( NOW, torrent->peer_list );

  peer_pool = &torrent->peer_list->peers[0];
  peer_dest = vector_find_or_insert( peer_pool, (void*)peer, sizeof( ot_peer ), OT_PEER_COMPARE_SIZE, &exactmatch );

  if( OT_FLAG(peer) & PEER_FLAG_COMPLETED )
    torrent->peer_list->downloaded++;

  /* If we hadn't had a match in current pool, create peer there and
     remove it from all older pools */
  if( !exactmatch ) {
    int i;
    memmove( peer_dest, peer, sizeof( ot_peer ) );
    if( OT_FLAG(peer) & PEER_FLAG_SEEDING )
      torrent->peer_list->seed_count[0]++;

    for( i=1; i<OT_POOLS_COUNT; ++i ) {
      switch( vector_remove_peer( &torrent->peer_list->peers[i], peer ) ) {
        case 0: continue;
        case 2: torrent->peer_list->seed_count[i]--;
        case 1: default: return torrent;
      }
    }
  } else {
    if( (OT_FLAG(peer_dest) & PEER_FLAG_SEEDING ) && !(OT_FLAG(peer) & PEER_FLAG_SEEDING ) )
      torrent->peer_list->seed_count[0]--;
    if( !(OT_FLAG(peer_dest) & PEER_FLAG_SEEDING ) && (OT_FLAG(peer) & PEER_FLAG_SEEDING ) )
      torrent->peer_list->seed_count[0]++;
    memmove( peer_dest, peer, sizeof( ot_peer ) );
  }

  return torrent;
}

/* Compiles a list of random peers for a torrent
   * reply must have enough space to hold 24+6*amount bytes
   * Selector function can be anything, maybe test for seeds, etc.
   * RANDOM may return huge values
   * does not yet check not to return self
*/
size_t return_peers_for_torrent( ot_torrent *torrent, size_t amount, char *reply ) {
  char  *r = reply;
  size_t peer_count, seed_count, index;

#ifdef WANT_CLOSED_TRACKER
  if( torrent == OT_TORRENT_NOT_ON_WHITELIST ) {
    const char * const notvalid = "d14:failure reason43:This torrent is not served by this tracker.e";
    memmove( reply, notvalid, sizeof(notvalid));
    return sizeof(notvalid);
  }
#endif

#ifdef WANT_BLACKLIST
  if( torrent == OT_TORRENT_ON_BLACKLIST ) {
    const char * const blacklisted = "d14:failure reason29:This torrent is black listed.e";
    memmove( reply, blacklisted, sizeof(blacklisted));
    return sizeof(blacklisted);
  }
#endif

  for( peer_count = seed_count = index = 0; index < OT_POOLS_COUNT; ++index ) {
    peer_count += torrent->peer_list->peers[index].size;
    seed_count += torrent->peer_list->seed_count[index];
  }
  if( peer_count < amount ) amount = peer_count;

  r += sprintf( r, "d8:completei%zde10:incompletei%zde8:intervali%ie5:peers%zd:", seed_count, peer_count-seed_count, OT_CLIENT_REQUEST_INTERVAL_RANDOM, 6*amount );
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
  *r++ = 'e';

  return r - reply;
}

/* Fetch full scrape info for all torrents */
size_t return_fullscrape_for_tracker( char **reply ) {
  size_t torrent_count = 0, j;
  int    i, k;
  char  *r;
  time_t time_now = NOW;

  for( i=0; i<256; ++i ) {
    ot_vector *torrents_list = &all_torrents[i];
    torrent_count += torrents_list->size;
  }

  if( !( r = *reply = malloc( 128*torrent_count ) ) ) return 0;

  memmove( r, "d5:filesd", 9 ); r += 9;
  for( i=0; i<256; ++i ) {
    ot_vector *torrents_list = &all_torrents[i];
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      ot_hash     *hash      =&( ((ot_torrent*)(torrents_list->data))[j] ).hash;
      size_t       peers = 0, seeds = 0;
      clean_peerlist( time_now, peer_list );
      for( k=0; k<OT_POOLS_COUNT; ++k ) {
        peers += peer_list->peers[k].size;
        seeds += peer_list->seed_count[k];
      }
      memmove( r, "20:", 3 ); r+=3;
      memmove( r, hash, 20 ); r+=20;
      r += sprintf( r, "d8:completei%zde10:downloadedi%zde10:incompletei%zdee", seeds, peer_list->downloaded, peers-seeds );
    }
  }

  *r++='e'; *r++='e';
  return r - *reply;
}

/* Fetches scrape info for a specific torrent */
size_t return_scrape_for_torrent( ot_hash *hash, char *reply ) {
  char        *r = reply;
  int          exactmatch, i;
  size_t       peers = 0, seeds = 0;
  ot_vector   *torrents_list = &all_torrents[*hash[0]];
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );

  if( !exactmatch ) return sprintf( r, "d5:filesdee" );
  clean_peerlist( NOW, torrent->peer_list );

  for( i=0; i<OT_POOLS_COUNT; ++i ) {
    peers += torrent->peer_list->peers[i].size;
    seeds += torrent->peer_list->seed_count[i];
  }

  memmove( r, "d5:filesd20:", 12 ); memmove( r+12, hash, 20 );
  r += sprintf( r+32, "d8:completei%zde10:downloadedi%zde10:incompletei%zdeeee", seeds, torrent->peer_list->downloaded, peers-seeds ) + 32;

  return r - reply;
}

size_t return_sync_for_torrent( ot_hash *hash, char **reply ) {
  int         exactmatch;
  size_t      peers = 0;
  char       *r;
  ot_vector  *torrents_list = &all_torrents[*hash[0]];
  ot_torrent *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );

  if( exactmatch ) {
    clean_peerlist( NOW, torrent->peer_list );
    peers = torrent->peer_list->peers[0].size;
  }

  if( !( r = *reply = malloc( 10 + peers * sizeof( ot_peer ) ) ) ) return 0;

  memmove( r, "d4:sync", 7 );
  r += 7;
  r += sprintf( r, "%zd:", peers * sizeof( ot_peer ) );
  if( peers ) {
    memmove( r, torrent->peer_list->peers[0].data, peers * sizeof( ot_peer ) );
    r += peers * sizeof( ot_peer );
  }
  *r++ = 'e';
  return r - *reply;
}

typedef struct { int val; ot_torrent * torrent; } ot_record;

/* Fetches stats from tracker */
size_t return_stats_for_tracker( char *reply, int mode ) {
  time_t    time_now = NOW;
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
      clean_peerlist( time_now, peer_list );
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
        r += sprintf( r, "\t%i\t%s\n", top5c[idx].val, to_hex(top5c[idx].torrent->hash) );
    r += sprintf( r, "Top5 torrents by seeds:\n" );
    for( idx=0; idx<5; ++idx )
      if( top5s[idx].torrent )
        r += sprintf( r, "\t%i\t%s\n", top5s[idx].val, to_hex(top5s[idx].torrent->hash) );
  } else {
    r += sprintf( r, "%zd\n%zd\nopentracker serving %zd torrents\nopentracker", peer_count, seed_count, torrent_count );
  }

  return r - reply;
}

void remove_peer_from_torrent( ot_hash *hash, ot_peer *peer ) {
  int          exactmatch, i;
  ot_vector   *torrents_list = &all_torrents[*hash[0]];
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );

  if( !exactmatch ) return;

  /* Maybe this does the job */
  if( clean_peerlist( NOW, torrent->peer_list ) ) {
#ifdef WANT_CLOSED_TRACKER
    if( !g_closedtracker )
#endif
    vector_remove_torrent( torrents_list, hash );
    return;
  }

  for( i=0; i<OT_POOLS_COUNT; ++i )
    switch( vector_remove_peer( &torrent->peer_list->peers[i], peer ) ) {
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
  byte_zero( all_torrents, sizeof (all_torrents) );

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
}
