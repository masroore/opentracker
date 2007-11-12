/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

/* System */
#include <sys/uio.h>
#include <stdio.h>
#include <string.h>

/* Libowfat */

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_iovec.h"
#include "ot_fullscrape.h"

/* Fetch full scrape info for all torrents
   Full scrapes usually are huge and one does not want to
   allocate more memory. So lets get them in 1M units
*/
#define OT_SCRAPE_CHUNK_SIZE (256*1024)

/* "d8:completei%zde10:downloadedi%zde10:incompletei%zdee" */
#define OT_FULLSCRAPE_MAXENTRYLEN 100

size_t return_fullscrape_for_tracker( int *iovec_entries, struct iovec **iovector ) {
  int    bucket;
  char  *r, *re;

  /* Setup return vector... */
  *iovec_entries = 0;
  if( !( r = iovec_increase( iovec_entries, iovector, OT_SCRAPE_CHUNK_SIZE ) ) )
    return 0;

  /* ... and pointer to end of current output buffer.
     This works as a low watermark */
  re = r + OT_SCRAPE_CHUNK_SIZE;

  /* Start reply dictionary */
  memmove( r, "d5:filesd", 9 ); r += 9;

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

      /* If torrent has peers or download count, its interesting */
      if( peer_list->peer_count || peer_list->down_count ) {

        /* push hash as bencoded string */
        *r++='2'; *r++='0'; *r++=':';
        memmove( r, hash, 20 ); r+=20;

        /* push rest of the scrape string */
        r += sprintf( r, "d8:completei%zde10:downloadedi%zde10:incompletei%zdee", peer_list->seed_count, peer_list->down_count, peer_list->peer_count-peer_list->seed_count );
      }

      /* If we reached our low watermark in buffer... */
      if( re - r <= OT_FULLSCRAPE_MAXENTRYLEN ) {

        /* crop current output buffer to the amount really used */
        iovec_fixlast( iovec_entries, iovector, OT_SCRAPE_CHUNK_SIZE - ( re - r ) );
        
        /* And allocate a fresh output buffer at the end of our buffers list */
        if( !( r = iovec_increase( iovec_entries, iovector, OT_SCRAPE_CHUNK_SIZE ) ) ) {
        
          /* If this fails: free buffers */
          iovec_free( iovec_entries, iovector );

          /* Release lock on current bucket and return */
          mutex_bucket_unlock( bucket );
          return 0;
        }
        
        /* Adjust new end of output buffer */
        re = r + OT_SCRAPE_CHUNK_SIZE;
      }
    }
    
    /* All torrents done: release lock on currenct bucket */
    mutex_bucket_unlock( bucket );
  }

  /* Close bencoded scrape dictionary */
  *r++='e'; *r++='e';

  /* Release unused memory in current output buffer */
  iovec_fixlast( iovec_entries, iovector, OT_SCRAPE_CHUNK_SIZE - ( re - r ) );

  /* Return answer size */
  return iovec_length( iovec_entries, iovector );
}
