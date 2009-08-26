/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>

/* Opentracker */
#include "trackerlogic.h"
#include "ot_vector.h"

/* Libowfat */
#include "uint32.h"
#include "uint16.h"

static int vector_compare_peer(const void *peer1, const void *peer2 ) {
  return memcmp( peer1, peer2, OT_PEER_COMPARE_SIZE );
}

/* This function gives us a binary search that returns a pointer, even if
   no exact match is found. In that case it sets exactmatch 0 and gives
   calling functions the chance to insert data
*/
void *binary_search( const void * const key, const void * base, const size_t member_count, const size_t member_size,
                     size_t compare_size, int *exactmatch ) {
  size_t interval = member_count;

  while( interval ) {
    uint8_t *lookat = ((uint8_t*)base) + member_size * ( interval / 2 );
    int cmp = memcmp( lookat, key, compare_size );
    if(cmp == 0 ) {
      base = lookat;
      break;
    }
    if(cmp < 0) {
      base = lookat + member_size;
      interval--;
    }
    interval /= 2;
  }

  *exactmatch = interval;
  return (void*)base;
}

static uint8_t vector_hash_peer( ot_peer *peer, int bucket_count ) {
  unsigned int hash = 5381, i = OT_PEER_COMPARE_SIZE;
  uint8_t *p = (uint8_t*)peer;
  while( i-- ) hash += (hash<<5) + *(p++);
  return hash % bucket_count;
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

  if( *exactmatch ) return match;

  if( vector->size + 1 > vector->space ) {
    size_t   new_space = vector->space ? OT_VECTOR_GROW_RATIO * vector->space : OT_VECTOR_MIN_MEMBERS;
    uint8_t *new_data = realloc( vector->data, new_space * member_size );
    if( !new_data ) return NULL;
    /* Adjust pointer if it moved by realloc */
    match = new_data + (match - (uint8_t*)vector->data);

    vector->data = new_data;
    vector->space = new_space;
  }
  memmove( match + member_size, match, ((uint8_t*)vector->data) + member_size * vector->size - match );

  vector->size++;
  return match;
}

ot_peer *vector_find_or_insert_peer( ot_vector *vector, ot_peer *peer, int *exactmatch ) {
  ot_peer *match;

  /* If space is zero but size is set, we're dealing with a list of vector->size buckets */
  if( vector->space < vector->size )
    vector = ((ot_vector*)vector->data) + vector_hash_peer(peer, vector->size );
  match = (ot_peer*)binary_search( peer, vector->data, vector->size, sizeof(ot_peer), OT_PEER_COMPARE_SIZE, exactmatch );

  if( *exactmatch ) return match;

  if( vector->size + 1 > vector->space ) {
    size_t   new_space = vector->space ? OT_VECTOR_GROW_RATIO * vector->space : OT_VECTOR_MIN_MEMBERS;
    ot_peer *new_data = realloc( vector->data, new_space * sizeof(ot_peer) );
    if( !new_data ) return NULL;
    /* Adjust pointer if it moved by realloc */
    match = new_data + (match - (ot_peer*)vector->data);

    vector->data = new_data;
    vector->space = new_space;
  }
  memmove( match + 1, match, sizeof(ot_peer) * ( ((ot_peer*)vector->data) + vector->size - match ) );

  vector->size++;
  return match;
}

/* This is the non-generic delete from vector-operation specialized for peers in pools.
   It returns 0 if no peer was found (and thus not removed)
              1 if a non-seeding peer was removed
              2 if a seeding peer was removed
*/
int vector_remove_peer( ot_vector *vector, ot_peer *peer ) {
  int      exactmatch;
  ot_peer *match, *end;

  if( !vector->size ) return 0;

  /* If space is zero but size is set, we're dealing with a list of vector->size buckets */
  if( vector->space < vector->size )
    vector = ((ot_vector*)vector->data) + vector_hash_peer(peer, vector->size );

  end = ((ot_peer*)vector->data) + vector->size;
  match = (ot_peer*)binary_search( peer, vector->data, vector->size, sizeof(ot_peer), OT_PEER_COMPARE_SIZE, &exactmatch );
  if( !exactmatch ) return 0;

  exactmatch = ( OT_PEERFLAG( match ) & PEER_FLAG_SEEDING ) ? 2 : 1;
  memmove( match, match + 1, sizeof(ot_peer) * ( end - match - 1 ) );

  vector->size--;
  vector_fixup_peers( vector );
  return exactmatch;
}

void vector_remove_torrent( ot_vector *vector, ot_torrent *match ) {
  ot_torrent *end = ((ot_torrent*)vector->data) + vector->size;

  if( !vector->size ) return;

  /* If this is being called after a unsuccessful malloc() for peer_list
     in add_peer_to_torrent, match->peer_list actually might be NULL */
  if( match->peer_list) free_peerlist( match->peer_list );

  memmove( match, match + 1, sizeof(ot_torrent) * ( end - match - 1 ) );
  if( ( --vector->size * OT_VECTOR_SHRINK_THRESH < vector->space ) && ( vector->space >= OT_VECTOR_SHRINK_RATIO * OT_VECTOR_MIN_MEMBERS ) ) {
    vector->space /= OT_VECTOR_SHRINK_RATIO;
    vector->data = realloc( vector->data, vector->space * sizeof( ot_torrent ) );
  }
}

void vector_clean_list( ot_vector * vector, int num_buckets ) {
  while( num_buckets-- )
    free( vector[num_buckets].data );
  free( vector );
  return;
}

void vector_redistribute_buckets( ot_peerlist * peer_list ) {
  int tmp, bucket, bucket_size_new, num_buckets_new, num_buckets_old = 1;
  ot_vector * bucket_list_new, * bucket_list_old = &peer_list->peers;

  if( OT_PEERLIST_HASBUCKETS( peer_list ) ) {
    num_buckets_old = peer_list->peers.size;
    bucket_list_old = peer_list->peers.data;
  }

  if( peer_list->peer_count < 255 )
    num_buckets_new = 1;
  else if( peer_list->peer_count > 8192 )
    num_buckets_new = 64;
  else if( peer_list->peer_count >= 512 && peer_list->peer_count < 4096 )
    num_buckets_new = 16;
  else if( peer_list->peer_count < 512 && num_buckets_old <= 16 )
    num_buckets_new = num_buckets_old;
  else if( peer_list->peer_count < 512 )
    num_buckets_new = 1;
  else if( peer_list->peer_count < 8192 && num_buckets_old > 1 )
    num_buckets_new = num_buckets_old;
  else
    num_buckets_new = 16;

  if( num_buckets_new == num_buckets_old )
    return;

  /* Assume near perfect distribution */
  bucket_list_new = malloc( num_buckets_new * sizeof( ot_vector ) );
  if( !bucket_list_new) return;
  bzero( bucket_list_new, num_buckets_new * sizeof( ot_vector ) );

  tmp = peer_list->peer_count / num_buckets_new;
  bucket_size_new = OT_VECTOR_MIN_MEMBERS;
  while( bucket_size_new < tmp)
    bucket_size_new *= OT_VECTOR_GROW_RATIO;

  /* preallocate vectors to hold all peers */
  for( bucket=0; bucket<num_buckets_new; ++bucket ) {
    bucket_list_new[bucket].space = bucket_size_new;
    bucket_list_new[bucket].data  = malloc( bucket_size_new * sizeof(ot_peer) );
    if( !bucket_list_new[bucket].data )
      return vector_clean_list( bucket_list_new, num_buckets_new );
  }

  /* Now sort them into the correct bucket */
  for( bucket=0; bucket<num_buckets_old; ++bucket ) {
    ot_peer * peers_old = bucket_list_old[bucket].data, * peers_new;
    int peer_count_old = bucket_list_old[bucket].size;
    while( peer_count_old-- ) {
      ot_vector * bucket_dest = bucket_list_new;
      if( num_buckets_new > 1 )
        bucket_dest += vector_hash_peer(peers_old, num_buckets_new);
      if( bucket_dest->size + 1 > bucket_dest->space ) {
        void * tmp = realloc( bucket_dest->data, sizeof(ot_peer) * OT_VECTOR_GROW_RATIO * bucket_dest->space );
        if( !tmp ) return vector_clean_list( bucket_list_new, num_buckets_new );
        bucket_dest->data   = tmp;
        bucket_dest->space *= OT_VECTOR_GROW_RATIO;
      }
      peers_new = (ot_peer*)bucket_dest->data;
      memcpy(peers_new + bucket_dest->size++, peers_old++, sizeof(ot_peer));
    }
  }

  /* Now sort each bucket to later allow bsearch */
  for( bucket=0; bucket<num_buckets_new; ++bucket )
    qsort( bucket_list_new[bucket].data, bucket_list_new[bucket].size, sizeof( ot_peer ), vector_compare_peer );

  /* Everything worked fine. Now link new bucket_list to peer_list */
  if( OT_PEERLIST_HASBUCKETS( peer_list) )
    vector_clean_list( (ot_vector*)peer_list->peers.data, peer_list->peers.size );
  else
    free( peer_list->peers.data );

  if( num_buckets_new > 1 ) {
    peer_list->peers.data  = bucket_list_new;
    peer_list->peers.size  = num_buckets_new;
    peer_list->peers.space = 0; /* Magic marker for "is list of buckets" */
  } else {
    peer_list->peers.data  = bucket_list_new->data;
    peer_list->peers.size  = bucket_list_new->size;
    peer_list->peers.space = bucket_list_new->space;
    free( bucket_list_new );
  }
}

void vector_fixup_peers( ot_vector * vector ) {
  int need_fix = 0;

  if( !vector->size ) {
    free( vector->data );
    vector->data = NULL;
    vector->space = 0;
    return;
  }

  while( ( vector->size * OT_VECTOR_SHRINK_THRESH < vector->space ) &&
         ( vector->space >= OT_VECTOR_SHRINK_RATIO * OT_VECTOR_MIN_MEMBERS ) ) {
    vector->space /= OT_VECTOR_SHRINK_RATIO;
    need_fix++;
  }
  if( need_fix )
    vector->data = realloc( vector->data, vector->space * sizeof( ot_peer ) );
}

const char *g_version_vector_c = "$Source$: $Revision$\n";
