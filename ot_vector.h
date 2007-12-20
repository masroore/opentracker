/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.
   
   $id$ */

#ifndef __OT_VECTOR_H__
#define __OT_VECTOR_H__

/* These defines control vectors behaviour */
#define OT_VECTOR_MIN_MEMBERS   4
#define OT_VECTOR_GROW_RATIO    8
#define OT_VECTOR_SHRINK_THRESH 6
#define OT_VECTOR_SHRINK_RATIO  4

typedef struct {
  void   *data;
  size_t  size;
  size_t  space;
} ot_vector;

void *binary_search( const void * const key, const void * base, const size_t member_count, const size_t member_size,
                     size_t compare_size, int *exactmatch );
void *vector_find_or_insert( ot_vector *vector, void *key, size_t member_size, size_t compare_size, int *exactmatch );

int   vector_remove_peer( ot_vector *vector, ot_peer *peer, int hysteresis );
void  vector_remove_torrent( ot_vector *vector, ot_torrent *match );

#endif
