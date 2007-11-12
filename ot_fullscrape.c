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
  size_t j;
  char  *r, *re;

  *iovec_entries = 0;
  if( !( r = iovec_increase( iovec_entries, iovector, OT_SCRAPE_CHUNK_SIZE ) ) )
    return 0;
  re = r + OT_SCRAPE_CHUNK_SIZE;

  memmove( r, "d5:filesd", 9 ); r += 9;
  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      ot_hash     *hash      =&( ((ot_torrent*)(torrents_list->data))[j] ).hash;
      if( peer_list->peer_count || peer_list->down_count ) {
        *r++='2'; *r++='0'; *r++=':';
        memmove( r, hash, 20 ); r+=20;
        r += sprintf( r, "d8:completei%zde10:downloadedi%zde10:incompletei%zdee", peer_list->seed_count, peer_list->down_count, peer_list->peer_count-peer_list->seed_count );
      }

      if( re - r <= OT_FULLSCRAPE_MAXENTRYLEN ) {
        iovec_fixlast( iovec_entries, iovector, OT_SCRAPE_CHUNK_SIZE - ( re - r ) );
        if( !( r = iovec_increase( iovec_entries, iovector, OT_SCRAPE_CHUNK_SIZE ) ) ) {
          iovec_free( iovec_entries, iovector );
          mutex_bucket_unlock( bucket );
          return 0;
        }
        re = r + OT_SCRAPE_CHUNK_SIZE;
      }
        
    }
    mutex_bucket_unlock( bucket );
  }

  *r++='e'; *r++='e';

  iovec_fixlast( iovec_entries, iovector, OT_SCRAPE_CHUNK_SIZE - ( re - r ) );

  return iovec_length( iovec_entries, iovector );
}
