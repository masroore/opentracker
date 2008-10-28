/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

/* Libowfat */
#include "scan.h"
#include "byte.h"
#include "io.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_sync.h"
#include "ot_stats.h"
#include "ot_iovec.h"

#ifdef WANT_SYNC_BATCH

#define OT_SYNC_CHUNK_SIZE (512*1024)

/* Import Changeset from an external authority
   format: d4:syncd[..]ee
   [..]:   ( 20:01234567890abcdefghij16:XXXXYYYY )+
*/
int add_changeset_to_tracker( uint8_t *data, size_t len ) {
  ot_hash    *hash;
  uint8_t    *end = data + len;
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
static void sync_make( int *iovec_entries, struct iovec **iovector ) {
  int    bucket;
  char  *r, *re;

  /* Setup return vector... */
  *iovec_entries = 0;
  *iovector = NULL;
  if( !( r = iovec_increase( iovec_entries, iovector, OT_SYNC_CHUNK_SIZE ) ) )
    return;

  /* ... and pointer to end of current output buffer.
     This works as a low watermark */
  re = r + OT_SYNC_CHUNK_SIZE;

  memmove( r, "d4:syncd", 8 ); r += 8;

  /* For each bucket... */
  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    /* Get exclusive access to that bucket */
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    size_t tor_offset;

    /* For each torrent in this bucket.. */
    for( tor_offset=0; tor_offset<torrents_list->size; ++tor_offset ) {
      /* Address torrents members */
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[tor_offset] ).peer_list;
      ot_hash     *hash      =&( ((ot_torrent*)(torrents_list->data))[tor_offset] ).hash;
      const size_t byte_count = sizeof(ot_peer) * peer_list->changeset.size;

      /* If we reached our low watermark in buffer... */
      if( re - r <= (ssize_t)(/* strlen( "20:" ) == */ 3 + sizeof( ot_hash ) + /* strlen_max( "%zd" ) == */ 12 + byte_count ) ) {

        /* Allocate a fresh output buffer at the end of our buffers list
           release bucket and return, if that fails */
        if( !( r = iovec_fix_increase_or_free( iovec_entries, iovector, r, OT_SYNC_CHUNK_SIZE ) ) )
          return mutex_bucket_unlock( bucket );

        /* Adjust new end of output buffer */
        re = r + OT_SYNC_CHUNK_SIZE;
      }

      *r++ = '2'; *r++ = '0'; *r++ = ':';
      memmove( r, hash, sizeof( ot_hash ) ); r += sizeof( ot_hash );
      r += sprintf( r, "%zd:", byte_count );
      memmove( r, peer_list->changeset.data, byte_count ); r += byte_count;
    }

    /* All torrents done: release lock on currenct bucket */
    mutex_bucket_unlock( bucket );
  }

  /* Close bencoded sync dictionary */
  *r++='e'; *r++='e';

  /* Release unused memory in current output buffer */
  iovec_fixlast( iovec_entries, iovector, r );
}

/* This is the entry point into this worker thread
   It grabs tasks from mutex_tasklist and delivers results back
*/
static void * sync_worker( void * args) {
  int iovec_entries;
  struct iovec *iovector;

  args = args;

  while( 1 ) {
    ot_tasktype tasktype = TASK_SYNC_OUT;
    ot_taskid   taskid   = mutex_workqueue_poptask( &tasktype );
    sync_make( &iovec_entries, &iovector );
    stats_issue_event( EVENT_SYNC_OUT, FLAG_TCP, iovec_length( &iovec_entries, &iovector) );
    if( mutex_workqueue_pushresult( taskid, iovec_entries, iovector ) )
      iovec_free( &iovec_entries, &iovector );
  }
  return NULL;
}

static pthread_t thread_id;
void sync_init( ) {
  pthread_create( &thread_id, NULL, sync_worker, NULL );
}

void sync_deinit( ) {
  pthread_cancel( thread_id );
}

void sync_deliver( int64 socket ) {
  mutex_workqueue_pushtask( socket, TASK_SYNC_OUT );
}

#endif

const char *g_version_sync_c = "$Source$: $Revision$\n";
