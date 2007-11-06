/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

/* System */
#include <sys/types.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>

/* Libowfat */
#include "scan.h"
#include "byte.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_sync.h"

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
  ot_vector *torrents_list;
  int    bucket;
  char   *r;

  /* Maybe there is time to clean_all_torrents(); */

  /* Determine space needed for whole changeset */
  for( bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket ) {
    torrents_list = mutex_bucket_lock(bucket);
    for( i=0; i<torrents_list->size; ++i ) {
      ot_torrent *torrent = ((ot_torrent*)(torrents_list->data)) + i;
      allocated += sizeof( ot_hash ) + sizeof(ot_peer) * torrent->peer_list->changeset.size + 13;
    }
    mutex_bucket_unlock(bucket);
  }

  /* add "d4:syncd" and "ee" */
  allocated += 8 + 2;

  if( !( r = *reply = mmap( NULL, allocated, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0 ) ) )
    return 0;

  memmove( r, "d4:syncd", 8 ); r += 8;
  for( bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket ) {
    torrents_list = mutex_bucket_lock(bucket);
    for( i=0; i<torrents_list->size; ++i ) {
      ot_torrent *torrent = ((ot_torrent*)(torrents_list->data)) + i;
      const size_t byte_count = sizeof(ot_peer) * torrent->peer_list->changeset.size;
      *r++ = '2'; *r++ = '0'; *r++ = ':';
      memmove( r, torrent->hash, sizeof( ot_hash ) ); r += sizeof( ot_hash );
      r += sprintf( r, "%zd:", byte_count );
      memmove( r, torrent->peer_list->changeset.data, byte_count ); r += byte_count;
    }
    mutex_bucket_unlock(bucket);
  }
  *r++ = 'e'; *r++ = 'e';

  replysize = ( r - *reply );
  fix_mmapallocation( *reply, allocated, replysize );

  return replysize;
}
#endif
