/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <stdlib.h>
#include <string.h>

/* Opentracker */
#include "trackerlogic.h"
#include "ot_vector.h"

#ifdef _DEBUG_VECTOR
#include <stdio.h>

static uint64_t vector_debug_inc[32];
static uint64_t vector_debug_noinc[32];
static uint64_t vector_debug_dec[32];
static uint64_t vector_debug_nodec[32];
static void vector_debug( size_t old_size, ssize_t diff_size, size_t old_space, ssize_t diff_space ) {
  int x = 0;
  while( old_space ) { old_space>>=1; ++x; }
  old_size = old_size;

  if( diff_size == -1 )
    if( diff_space ) vector_debug_dec[x]++; else vector_debug_nodec[x]++;
  else
    if( diff_space ) vector_debug_inc[x]++; else vector_debug_noinc[x]++;

}

size_t vector_info( char * reply ) {
  char * r = reply;
  int i;
  for( i=1; i<28; ++i )
    r += sprintf( r, "  inc % 12d -> % 12d: % 16lld\n", 1<<(i-1), 8<<(i-1), vector_debug_inc[i] );
  for( i=1; i<28; ++i )
    r += sprintf( r, "noinc % 12d -> % 12d: % 16lld\n", 1<<(i-1), 1<<(i-1), vector_debug_noinc[i] );
  for( i=1; i<28; ++i )
    r += sprintf( r, "  dec % 12d -> % 12d: % 16lld\n", 1<<(i-1), 4<<(i-1), vector_debug_dec[i] );
  for( i=1; i<28; ++i )
    r += sprintf( r, "nodec % 12d -> % 12d: % 16lld\n", 1<<(i-1), 1<<(i-1), vector_debug_nodec[i] );
  return r - reply;
}
#endif

/* This function gives us a binary search that returns a pointer, even if
   no exact match is found. In that case it sets exactmatch 0 and gives
   calling functions the chance to insert data
*/
void *binary_search( const void * const key, const void * base, const size_t member_count, const size_t member_size,
                     size_t compare_size, int *exactmatch ) {
  size_t mc = member_count;
  uint8_t *lookat = ((uint8_t*)base) + member_size * (member_count >> 1);
  *exactmatch = 1;

  while( mc ) {
    int cmp = memcmp( lookat, key, compare_size);
    if (cmp == 0) return (void *)lookat;
    if (cmp < 0) {
      base = (void*)(lookat + member_size);
      --mc;
    }
    mc >>= 1;
    lookat = ((uint8_t*)base) + member_size * (mc >> 1);
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
void *vector_find_or_insert( ot_vector *vector, void *key, size_t member_size, size_t compare_size, int *exactmatch ) {
  uint8_t *match = binary_search( key, vector->data, vector->size, member_size, compare_size, exactmatch );
#ifdef _DEBUG_VECTOR
  size_t old_space = vector->space;
#endif

  if( *exactmatch ) return match;

  if( vector->size + 1 >= vector->space ) {
    size_t   new_space = vector->space ? OT_VECTOR_GROW_RATIO * vector->space : OT_VECTOR_MIN_MEMBERS;
    uint8_t *new_data = realloc( vector->data, new_space * member_size );
    if( !new_data ) return NULL;

    /* Adjust pointer if it moved by realloc */
    match = new_data + (match - (uint8_t*)vector->data);

    vector->data = new_data;
    vector->space = new_space;
  }
  memmove( match + member_size, match, ((uint8_t*)vector->data) + member_size * vector->size - match );

#ifdef _DEBUG_VECTOR
  vector_debug( vector->size, 1, old_space, vector->space - old_space );
#endif
  vector->size++;
  return match;
}

/* This is the non-generic delete from vector-operation specialized for peers in pools.
   Set hysteresis == 0 if you expect the vector not to ever grow again.
   It returns 0 if no peer was found (and thus not removed)
              1 if a non-seeding peer was removed
              2 if a seeding peer was removed
*/
int vector_remove_peer( ot_vector *vector, ot_peer *peer, int hysteresis ) {
  int      exactmatch;
  size_t   shrink_thresh = hysteresis ? OT_VECTOR_SHRINK_THRESH : OT_VECTOR_SHRINK_RATIO;
  ot_peer *end = ((ot_peer*)vector->data) + vector->size;
  ot_peer *match;
#ifdef _DEBUG_VECTOR
  size_t   old_space = vector->space;
#endif

  if( !vector->size ) return 0;
  match = binary_search( peer, vector->data, vector->size, sizeof( ot_peer ), OT_PEER_COMPARE_SIZE, &exactmatch );

  if( !exactmatch ) return 0;
  exactmatch = ( OT_FLAG( match ) & PEER_FLAG_SEEDING ) ? 2 : 1;
  memmove( match, match + 1, sizeof(ot_peer) * ( end - match - 1 ) );
  if( ( --vector->size * shrink_thresh < vector->space ) && ( vector->space >= OT_VECTOR_SHRINK_RATIO * OT_VECTOR_MIN_MEMBERS ) ) {
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
#ifdef _DEBUG_VECTOR
  vector_debug( vector->size+1, -1, old_space, vector->space - old_space );
#endif
  return exactmatch;
}

void vector_remove_torrent( ot_vector *vector, ot_torrent *match ) {
  ot_torrent *end = ((ot_torrent*)vector->data) + vector->size;
#ifdef _DEBUG_VECTOR
  size_t      old_space = vector->space;
#endif

  if( !vector->size ) return;

  /* If this is being called after a unsuccessful malloc() for peer_list
     in add_peer_to_torrent, match->peer_list actually might be NULL */
  if( match->peer_list) free_peerlist( match->peer_list );

  memmove( match, match + 1, sizeof(ot_torrent) * ( end - match - 1 ) );
  if( ( --vector->size * OT_VECTOR_SHRINK_THRESH < vector->space ) && ( vector->space >= OT_VECTOR_SHRINK_RATIO * OT_VECTOR_MIN_MEMBERS ) ) {
    vector->space /= OT_VECTOR_SHRINK_RATIO;
    vector->data = realloc( vector->data, vector->space * sizeof( ot_torrent ) );
  }
#ifdef _DEBUG_VECTOR
  vector_debug( vector->size+1, -1, old_space, vector->space - old_space );
#endif
}

const char *g_version_vector_c = "$Source$: $Revision$\n";
