/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifdef WANT_FULLSCRAPE

/* System */
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#ifdef WANT_COMPRESSION_GZIP
#include <zlib.h>
#endif

/* Libowfat */
#include "byte.h"
#include "io.h"
#include "textcode.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_iovec.h"
#include "ot_fullscrape.h"

/* Fetch full scrape info for all torrents
   Full scrapes usually are huge and one does not want to
   allocate more memory. So lets get them in 512k units
*/
#define OT_SCRAPE_CHUNK_SIZE (512*1024)

/* "d8:completei%zde10:downloadedi%zde10:incompletei%zdee" */
#define OT_SCRAPE_MAXENTRYLEN 256

#ifdef WANT_COMPRESSION_GZIP
#define IF_COMPRESSION( TASK ) if( mode & TASK_FLAG_GZIP ) TASK
#define WANT_COMPRESSION_GZIP_PARAM( param1, param2, param3 ) , param1, param2, param3
#else
#define IF_COMPRESSION( TASK )
#define WANT_COMPRESSION_GZIP_PARAM( param1, param2, param3 )
#endif

/* Forward declaration */
static void fullscrape_make( int *iovec_entries, struct iovec **iovector, ot_tasktype mode );

/* Converter function from memory to human readable hex strings
   XXX - Duplicated from ot_stats. Needs fix. */
static char*to_hex(char*d,uint8_t*s){char*m="0123456789ABCDEF";char *t=d;char*e=d+40;while(d<e){*d++=m[*s>>4];*d++=m[*s++&15];}*d=0;return t;}

/* This is the entry point into this worker thread
   It grabs tasks from mutex_tasklist and delivers results back
*/
static void * fullscrape_worker( void * args ) {
  int iovec_entries;
  struct iovec *iovector;

  (void) args;

  while( 1 ) {
    ot_tasktype tasktype = TASK_FULLSCRAPE;
    ot_taskid   taskid   = mutex_workqueue_poptask( &tasktype );
    fullscrape_make( &iovec_entries, &iovector, tasktype );
    if( mutex_workqueue_pushresult( taskid, iovec_entries, iovector ) )
      iovec_free( &iovec_entries, &iovector );
    if( !g_opentracker_running )
      return NULL;
  }
  return NULL;
}

static pthread_t thread_id;
void fullscrape_init( ) {
  pthread_create( &thread_id, NULL, fullscrape_worker, NULL );
}

void fullscrape_deinit( ) {
  pthread_cancel( thread_id );
}

void fullscrape_deliver( int64 sock, ot_tasktype tasktype ) {
  mutex_workqueue_pushtask( sock, tasktype );
}

static int fullscrape_increase( int *iovec_entries, struct iovec **iovector,
                         char **r, char **re  WANT_COMPRESSION_GZIP_PARAM( z_stream *strm, ot_tasktype mode, int zaction ) ) {
  /* Allocate a fresh output buffer at the end of our buffers list */
  if( !( *r = iovec_fix_increase_or_free( iovec_entries, iovector, *r, OT_SCRAPE_CHUNK_SIZE ) ) ) {

    /* Deallocate gzip buffers */
    IF_COMPRESSION( deflateEnd(strm); )

    /* Release lock on current bucket and return */
    return -1;
  }

  /* Adjust new end of output buffer */
  *re = *r + OT_SCRAPE_CHUNK_SIZE - OT_SCRAPE_MAXENTRYLEN;

  /* When compressing, we have all the bytes in output buffer */
#ifdef WANT_COMPRESSION_GZIP
  if( mode & TASK_FLAG_GZIP ) {
    int zres;
    *re -= OT_SCRAPE_MAXENTRYLEN;
    strm->next_out  = (uint8_t*)*r;
    strm->avail_out = OT_SCRAPE_CHUNK_SIZE;
    zres = deflate( strm, zaction );
    if( ( zres < Z_OK ) && ( zres != Z_BUF_ERROR ) )
      fprintf( stderr, "deflate() failed while in fullscrape_increase(%d).\n", zaction );
    *r = (char*)strm->next_out;
  }
#endif

  return 0;
}

static void fullscrape_make( int *iovec_entries, struct iovec **iovector, ot_tasktype mode ) {
  int      bucket;
  char    *r, *re;
#ifdef WANT_COMPRESSION_GZIP
  char     compress_buffer[OT_SCRAPE_MAXENTRYLEN];
  z_stream strm;
#endif

  /* Setup return vector... */
  *iovec_entries = 0;
  *iovector = NULL;
  if( !( r = iovec_increase( iovec_entries, iovector, OT_SCRAPE_CHUNK_SIZE ) ) )
    return;

  /* re points to low watermark */
  re = r + OT_SCRAPE_CHUNK_SIZE - OT_SCRAPE_MAXENTRYLEN;

#ifdef WANT_COMPRESSION_GZIP
  if( mode & TASK_FLAG_GZIP ) {
    re += OT_SCRAPE_MAXENTRYLEN;
    byte_zero( &strm, sizeof(strm) );
    strm.next_in   = (uint8_t*)compress_buffer;
    strm.next_out  = (uint8_t*)r;
    strm.avail_out = OT_SCRAPE_CHUNK_SIZE;
    if( deflateInit2(&strm,7,Z_DEFLATED,31,8,Z_DEFAULT_STRATEGY) != Z_OK )
      fprintf( stderr, "not ok.\n" );
    r = compress_buffer;
  }
#endif

  if( ( mode & TASK_TASK_MASK ) == TASK_FULLSCRAPE )
    r += sprintf( r, "d5:filesd" );

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

      switch( mode & TASK_TASK_MASK ) {
      case TASK_FULLSCRAPE:
      default:
        /* push hash as bencoded string */
        *r++='2'; *r++='0'; *r++=':';
        memcpy( r, hash, sizeof(ot_hash) ); r += sizeof(ot_hash);
        /* push rest of the scrape string */
        r += sprintf( r, "d8:completei%zde10:downloadedi%zde10:incompletei%zdee", peer_list->seed_count, peer_list->down_count, peer_list->peer_count-peer_list->seed_count );

        break;
      case TASK_FULLSCRAPE_TPB_ASCII:
        to_hex( r, *hash ); r+= 2 * sizeof(ot_hash);
        r += sprintf( r, ":%zd:%zd\n", peer_list->seed_count, peer_list->peer_count-peer_list->seed_count );
        break;
      case TASK_FULLSCRAPE_TPB_BINARY:
        memcpy( r, *hash, sizeof(ot_hash) ); r += sizeof(ot_hash);
        *(uint32_t*)(r+0) = htonl( (uint32_t)  peer_list->seed_count );
        *(uint32_t*)(r+4) = htonl( (uint32_t)( peer_list->peer_count-peer_list->seed_count) );
        r+=8;
        break;
      case TASK_FULLSCRAPE_TPB_URLENCODED:
        r += fmt_urlencoded( r, (char *)*hash, 20 );
        r += sprintf( r, ":%zd:%zd\n", peer_list->seed_count, peer_list->peer_count-peer_list->seed_count );
        break;
      case TASK_FULLSCRAPE_TRACKERSTATE:
        to_hex( r, *hash ); r+= 2 * sizeof(ot_hash);
        r += sprintf( r, ":%zd:%zd\n", peer_list->base, peer_list->down_count );
        break;
      }

#ifdef WANT_COMPRESSION_GZIP
     if( mode & TASK_FLAG_GZIP ) {
        int zres;
        strm.next_in  = (uint8_t*)compress_buffer;
        strm.avail_in = r - compress_buffer;
        zres = deflate( &strm, Z_NO_FLUSH );
        if( ( zres < Z_OK ) && ( zres != Z_BUF_ERROR ) )
          fprintf( stderr, "deflate() failed while in fullscrape_make().\n" );
        r = (char*)strm.next_out;
      }
#endif

      /* Check if there still is enough buffer left */
      while( r >= re )
       if( fullscrape_increase( iovec_entries, iovector, &r, &re WANT_COMPRESSION_GZIP_PARAM( &strm, mode, Z_NO_FLUSH ) ) )
         return mutex_bucket_unlock( bucket, 0 );

      IF_COMPRESSION( r = compress_buffer; )
    }

    /* All torrents done: release lock on current bucket */
    mutex_bucket_unlock( bucket, 0 );

    /* Parent thread died? */
    if( !g_opentracker_running )
      return;
  }

  if( ( mode & TASK_TASK_MASK ) == TASK_FULLSCRAPE )
    r += sprintf( r, "ee" );

#ifdef WANT_COMPRESSION_GZIP
  if( mode & TASK_FLAG_GZIP ) {
    strm.next_in  = (uint8_t*)compress_buffer;
    strm.avail_in = r - compress_buffer;
    if( deflate( &strm, Z_FINISH ) < Z_OK )
      fprintf( stderr, "deflate() failed while in fullscrape_make()'s endgame.\n" );
    r = (char*)strm.next_out;

    while( r >= re )
      if( fullscrape_increase( iovec_entries, iovector, &r, &re WANT_COMPRESSION_GZIP_PARAM( &strm, mode, Z_FINISH ) ) )
        return mutex_bucket_unlock( bucket, 0 );
    deflateEnd(&strm);
  }
#endif

  /* Release unused memory in current output buffer */
  iovec_fixlast( iovec_entries, iovector, r );
}
#endif

const char *g_version_fullscrape_c = "$Source$: $Revision$\n";
