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

// Helper functions for binary_find
//
int compare_hash( const void *hash1, const void *hash2 ) { return memcmp( hash1, hash2, sizeof( ot_hash )); }
int compare_ip_port( const void *peer1, const void *peer2 ) {
if( ((ot_peer)peer1)->ip != ((ot_peer)peer2)->ip ) return ((ot_peer)peer1)->ip - ((ot_peer)peer2)->ip;
return ((ot_peer)peer1)->port_flags - ((ot_peer)peer2)->port_flags; }

void *binary_search( const void *key, const void *base,
                     unsigned long member_count, const unsigned long member_size,
                     int (*compar) (const void *, const void *),
                     int *exactmatch ) {
  ot_byte *lookat = ((ot_byte*)base) + member_size * (member_count >> 1);
  *exactmatch = 1;

  while( member_count ) {
    int cmp = compar((void*)lookat, key);
    if (cmp == 0) return (void *)lookat;
    if (cmp < 0) {
      base = (void*)(lookat + member_size);
      --member_count;
    }
    member_count >>= 1;
    lookat = ((ot_byte*)base) + member_size * (member_count >> 1);
  }
  *exactmatch = 0;
  return (void*)lookat;

}

// Converter function from memory to human readable hex strings
// * definitely not thread safe!!!
//
char ths[1+2*20];char*to_hex(ot_byte*s){char*m="0123456789ABCDEF";char*e=ths+40;char*t=ths;while(t<e){*t++=m[*s>>4];*t++=m[*s++&15];}*t=0;return ths;}

// GLOBAL VARIABLES
//
struct ot_vector all_torrents[256];

void *vector_find_or_insert( ot_vector vector, void *key, size_t member_size, int(*compare_func)(const void*, const void*), int *exactmatch ) {
  ot_byte *match = BINARY_FIND( key, vector->data, vector->size, member_size, compare_func, exactmatch );

  if( *exactmatch ) return match;

  if( vector->size + 1 >= vector->space ) {
    ot_byte *new_data = realloc( vector->data, vector->space ? 2 * vector->space : 1024 );
    if( !new_data ) return NULL;

    // Adjust pointer if it moved by realloc
    match = match - (ot_byte*)vector->data + new_data;

    vector->data = new_data;
    vector->space = vector->space ? vector->space * 2 : 1024;
  }
  MEMMOVE( match + member_size, match, ((ot_byte*)vector->data) + member_size * vector->size - match );
  vector->size++;
  return match;
}

int vector_remove_peer( ot_vector vector, ot_peer peer ) {
  int exactmatch;
  ot_peer match;

  if( !vector->size ) return 0;
  match = BINARY_FIND( peer, vector->data, vector->size, sizeof( struct ot_peer ), compare_ip_port, &exactmatch );

  if( !exactmatch ) return 0;
  exactmatch = match->port_flags & PEER_FLAG_SEEDING ? 2 : 1;
  MEMMOVE( match, match + 1, ((ot_peer)vector->data) + vector->size - match - 1 );
  vector->size--;
  return exactmatch;
}

void free_peerlist( ot_peerlist peer_list ) {
  int i;
  for( i=0; i<OT_POOLS_COUNT; ++i )
    if( peer_list->peers[i].data )
      free( peer_list->peers[i].data );
  free( peer_list );
}

int vector_remove_torrent( ot_vector vector, ot_hash *hash ) {
  int exactmatch;
  ot_torrent end = ((ot_torrent)vector->data) + vector->size;
  ot_torrent match = BINARY_FIND( hash, vector->data, vector->size, sizeof( struct ot_torrent ), compare_hash, &exactmatch );

  if( !exactmatch ) return -1;
  free_peerlist( match->peer_list );
  MEMMOVE( match, match + 1, end - match - 1 );
  vector->size--;
  if( ( 3*vector->size < vector->space ) && ( vector->space > 1024 ) ) {
    realloc( vector->data, vector->space >> 1 );
    vector->space >>= 1;
  }
  return 0;
}

void clean_peerlist( ot_peerlist peer_list ) {
  long timedout = NOW-peer_list->base;
  int i;

  if( !timedout ) return;
  if( timedout > OT_POOLS_COUNT ) timedout = OT_POOLS_COUNT;

  for( i=OT_POOLS_COUNT-timedout; i<OT_POOLS_COUNT; ++i )
    free( peer_list->peers[i].data);

  MEMMOVE( peer_list->peers + timedout, peer_list->peers, sizeof( ot_vector ) * (OT_POOLS_COUNT-timedout) );
  byte_zero( peer_list->peers, sizeof( ot_vector ) * timedout );

  MEMMOVE( peer_list->seed_count + timedout, peer_list->seed_count, sizeof( unsigned long ) * (OT_POOLS_COUNT-timedout) );
  byte_zero( peer_list->seed_count, sizeof( unsigned long ) * timedout );

  peer_list->base = NOW;
}

ot_torrent add_peer_to_torrent( ot_hash *hash, ot_peer peer ) {
  int exactmatch;
  ot_torrent torrent;
  ot_peer    peer_dest;
  ot_vector  torrents_list = all_torrents + *hash[0], peer_pool;

  torrent = vector_find_or_insert( torrents_list, (void*)hash, sizeof( struct ot_torrent ), compare_hash, &exactmatch );
  if( !torrent ) return NULL;

  if( !exactmatch ) {
    // Create a new torrent entry, then
    torrent->peer_list = malloc( sizeof (struct ot_peerlist) );
    if( !torrent->peer_list ) {
      vector_remove_torrent( torrents_list, hash );
      return NULL;
    }
    MEMMOVE( &torrent->hash, hash, sizeof( ot_hash ) );

    byte_zero( torrent->peer_list, sizeof( struct ot_peerlist ));
    torrent->peer_list->base = NOW;
  } else
    clean_peerlist( torrent->peer_list );

  peer_pool = &torrent->peer_list->peers[0];
  peer_dest = vector_find_or_insert( peer_pool, (void*)peer, sizeof( struct ot_peer ), compare_ip_port, &exactmatch );

  // If we hadn't had a match in current pool, create peer there and
  // remove it from all older pools
  if( !exactmatch ) {
    int i;
    MEMMOVE( peer_dest, peer, sizeof( struct ot_peer ) );
    if( peer->port_flags & PEER_FLAG_SEEDING )
      torrent->peer_list->seed_count[0]++;
    for( i=1; i<OT_POOLS_COUNT; ++i ) {
      switch( vector_remove_peer( &torrent->peer_list->peers[i], peer ) ) {
        case 0: continue;
        case 2: torrent->peer_list->seed_count[i]--;
        case 1: default: return torrent;
      }
    }
  } else {
    if( (peer_dest->port_flags & PEER_FLAG_SEEDING ) && !(peer->port_flags & PEER_FLAG_SEEDING ) )
      torrent->peer_list->seed_count[0]--;
    if( !(peer_dest->port_flags & PEER_FLAG_SEEDING ) && (peer->port_flags & PEER_FLAG_SEEDING ) )
      torrent->peer_list->seed_count[0]++;
  }

  return torrent;
}

// Compiles a list of random peers for a torrent
// * reply must have enough space to hold 24+6*amount bytes
// * Selector function can be anything, maybe test for seeds, etc.
// * RANDOM may return huge values
// * does not yet check not to return self
//
size_t return_peers_for_torrent( ot_torrent torrent, unsigned long amount, char *reply ) {
  char           *r = reply;
  unsigned long  peer_count, index;
  signed   long  pool_offset = -1, pool_index = 0;
  signed   long  wert = -1;

  for( peer_count=index=0; index<OT_POOLS_COUNT; ++index) peer_count += torrent->peer_list->peers[index].size;
  if( peer_count < amount ) amount = peer_count;

  r += FORMAT_FORMAT_STRING( r, "d5:peers%li:",6*amount );
  for( index = 0; index < amount; ++index ) {
    double step = 1.8*((double)( peer_count - wert - 1 ))/((double)( amount - index ));
    int off = random() % (int)floor( step );
    off = 1 + ( off % ( peer_count - wert - 1 ));
    wert += off; pool_offset += off;

    while( pool_offset >= torrent->peer_list->peers[pool_index].size ) {
      pool_offset -= torrent->peer_list->peers[pool_index].size;
      pool_index++;
    }

    MEMMOVE( r, ((ot_peer*)torrent->peer_list->peers[pool_index].data) + pool_offset, 6 );
    r += 6;
  }
  *r++ = 'e';
  return r - reply;
}

int init_logic( char *directory ) {
  glob_t globber;
  int i;

  if( directory ) {
   if( chdir( directory ))
     return -1;
  }

  srandom( time(NULL));

  // Initialize control structures
  byte_zero( all_torrents, sizeof (all_torrents));

  // Scan directory for filenames in the form [0-9A-F]{20}
  // * I know this looks ugly, but I've seen A-F to match umlauts as well in strange locales
  // * lower case for .. better being safe than sorry, this is not expensive here :)
  if( !glob(
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    , GLOB_NOCHECK, 0, &globber) )
  {
    for( i=0; i<globber.gl_matchc; ++i )
      printf( "Found: %s\n", globber.gl_pathv[i] );
  }

  globfree( &globber );
  return 0;
}

void deinit_logic( ) {
  int i, j;
  // Free all torrents...
  for(i=0; i<256; ++i ) {
    if( all_torrents[i].size ) {
      ot_torrent torrents_list = (ot_torrent)all_torrents[i].data;
      for( j=0; j<all_torrents[i].size; ++j )
        free_peerlist( torrents_list[j].peer_list );
      free( all_torrents[i].data );
    }
  }
  byte_zero( all_torrents, sizeof (all_torrents));
}
