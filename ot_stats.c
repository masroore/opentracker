/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

/* System */
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>

/* Libowfat */
#include "byte.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_stats.h"

/* Clumsy counters... to be rethought */
static unsigned long long ot_overall_tcp_connections = 0;
static unsigned long long ot_overall_udp_connections = 0;
static unsigned long long ot_overall_tcp_successfulannounces = 0;
static unsigned long long ot_overall_udp_successfulannounces = 0;
static unsigned long long ot_overall_tcp_successfulscrapes = 0;
static unsigned long long ot_overall_udp_successfulscrapes = 0;
static unsigned long long ot_full_scrape_count = 0;
static unsigned long long ot_full_scrape_size = 0;

/* Converter function from memory to human readable hex strings */
static char*to_hex(char*d,ot_byte*s){char*m="0123456789ABCDEF";char *t=d;char*e=d+40;while(d<e){*d++=m[*s>>4];*d++=m[*s++&15];}*d=0;return t;}

typedef struct { size_t val; ot_torrent * torrent; } ot_record;

/* Fetches stats from tracker */
size_t stats_top5_txt( char * reply ) {
  size_t    j;
  ot_record top5s[5], top5c[5];
  char     *r  = reply, hex_out[42];
  int       idx, bucket;

  byte_zero( top5s, sizeof( top5s ) );
  byte_zero( top5c, sizeof( top5c ) );

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      int idx = 4; while( (idx >= 0) && ( peer_list->peer_count > top5c[idx].val ) ) --idx;
      if ( idx++ != 4 ) {
        memmove( top5c + idx + 1, top5c + idx, ( 4 - idx ) * sizeof( ot_record ) );
        top5c[idx].val = peer_list->peer_count;
        top5c[idx].torrent = (ot_torrent*)(torrents_list->data) + j;
      }
      idx = 4; while( (idx >= 0) && ( peer_list->seed_count > top5s[idx].val ) ) --idx;
      if ( idx++ != 4 ) {
        memmove( top5s + idx + 1, top5s + idx, ( 4 - idx ) * sizeof( ot_record ) );
        top5s[idx].val = peer_list->seed_count;
        top5s[idx].torrent = (ot_torrent*)(torrents_list->data) + j;
      }
    }
    mutex_bucket_unlock( bucket );
  }

  r += sprintf( r, "Top5 torrents by peers:\n" );
  for( idx=0; idx<5; ++idx )
    if( top5c[idx].torrent )
      r += sprintf( r, "\t%zd\t%s\n", top5c[idx].val, to_hex( hex_out, top5c[idx].torrent->hash) );
  r += sprintf( r, "Top5 torrents by seeds:\n" );
  for( idx=0; idx<5; ++idx )
    if( top5s[idx].torrent )
      r += sprintf( r, "\t%zd\t%s\n", top5s[idx].val, to_hex( hex_out, top5s[idx].torrent->hash) );

  return r - reply;
}

/* This function collects 4096 /24s in 4096 possible
   malloc blocks
*/
static size_t stats_slash24s_txt( char * reply, size_t amount, ot_dword thresh ) {

#define NUM_TOPBITS 12
#define NUM_LOWBITS (24-NUM_TOPBITS)
#define NUM_BUFS    (1<<NUM_TOPBITS)
#define NUM_S24S    (1<<NUM_LOWBITS)
#define MSK_S24S    (NUM_S24S-1)

  ot_dword *counts[ NUM_BUFS ];
  ot_dword  slash24s[amount*2];  /* first dword amount, second dword subnet */
  int       bucket;
  size_t    i, j, k, l;
  char     *r  = reply;

  byte_zero( counts, sizeof( counts ) );
  byte_zero( slash24s, amount * 2 * sizeof(ot_dword) );

  r += sprintf( r, "Stats for all /24s with more than %u announced torrents:\n\n", thresh );

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      for( k=0; k<OT_POOLS_COUNT; ++k ) {
        ot_peer *peers =    peer_list->peers[k].data;
        size_t   numpeers = peer_list->peers[k].size;
        for( l=0; l<numpeers; ++l ) {
          ot_dword s24 = ntohl(*(ot_dword*)(peers+l)) >> 8;
          ot_dword *count = counts[ s24 >> NUM_LOWBITS ];
          if( !count ) {
            count = malloc( sizeof(ot_dword) * NUM_S24S );
            if( !count )
              goto bailout_cleanup;
            byte_zero( count, sizeof( ot_dword ) * NUM_S24S );
            counts[ s24 >> NUM_LOWBITS ] = count;
          }
          count[ s24 & MSK_S24S ]++;
        }
      }
    }
    mutex_bucket_unlock( bucket );
  }

  k = l = 0; /* Debug: count allocated bufs */
  for( i=0; i < NUM_BUFS; ++i ) {
    ot_dword *count = counts[i];
    if( !counts[i] )
      continue;
    ++k; /* Debug: count allocated bufs */
    for( j=0; j < NUM_S24S; ++j ) {
      if( count[j] > thresh ) {
        /* This subnet seems to announce more torrents than the last in our list */
        int insert_pos = amount - 1;
        while( ( insert_pos >= 0 ) && ( count[j] > slash24s[ 2 * insert_pos ] ) )
          --insert_pos;
        ++insert_pos;
        memmove( slash24s + 2 * ( insert_pos + 1 ), slash24s + 2 * ( insert_pos ), 2 * sizeof( ot_dword ) * ( amount - insert_pos - 1 ) );
        slash24s[ 2 * insert_pos     ] = count[j];
        slash24s[ 2 * insert_pos + 1 ] = ( i << NUM_TOPBITS ) + j;
        if( slash24s[ 2 * amount - 2 ] > thresh )
          thresh = slash24s[ 2 * amount - 2 ];
      }
      if( count[j] ) ++l;
    }
    free( count );
  }

  r += sprintf( r, "Allocated bufs: %zd, used s24s: %zd\n", k, l );

  for( i=0; i < amount; ++i )
    if( slash24s[ 2*i ] >= thresh ) {
      ot_dword ip = slash24s[ 2*i +1 ];
      r += sprintf( r, "% 10ld %d.%d.%d.0/24\n", (long)slash24s[ 2*i ], (int)(ip >> 16), (int)(255 & ( ip >> 8 )), (int)(ip & 255) );
    }

  return r - reply;

bailout_cleanup:

  for( i=0; i < NUM_BUFS; ++i )
    free( counts[i] );

  return 0;
}

size_t return_memstat_for_tracker( char **reply ) {
  size_t torrent_count = 0, j;
  size_t allocated, replysize;
  ot_vector *torrents_list;
  int    bucket, k;
  char  *r;

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    torrents_list = mutex_bucket_lock(bucket);
    torrent_count += torrents_list->size;
    mutex_bucket_unlock(bucket);
  }

  allocated = OT_BUCKET_COUNT*32 + (43+OT_POOLS_COUNT*32)*torrent_count;
  if( !( r = *reply = mmap( NULL, allocated, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0 ) ) ) return 0;

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    torrents_list = mutex_bucket_lock(bucket);
    r += sprintf( r, "%02X: %08X %08X\n", bucket, (unsigned int)torrents_list->size, (unsigned int)torrents_list->space );
    mutex_bucket_unlock(bucket);
  }

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock(bucket);
    char hex_out[42];
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      ot_hash     *hash      =&( ((ot_torrent*)(torrents_list->data))[j] ).hash;
      r += sprintf( r, "\n%s:\n", to_hex( hex_out, (ot_byte*)hash) );
      for( k=0; k<OT_POOLS_COUNT; ++k )
        r += sprintf( r, "\t%05X %05X\n", ((unsigned int)peer_list->peers[k].size), (unsigned int)peer_list->peers[k].space );
    }
    mutex_bucket_unlock(bucket);
  }

  replysize = ( r - *reply );
  fix_mmapallocation( *reply, allocated, replysize );

  return replysize;
}

static unsigned long events_per_time( unsigned long long events, time_t t ) {
  return events / ( (unsigned int)t ? (unsigned int)t : 1 );
}

static size_t stats_connections_mrtg( char * reply ) {
  ot_time t = time( NULL ) - ot_start_time;
  return sprintf( reply,
    "%llu\n%llu\n%i seconds (%i hours)\nopentracker connections, %lu conns/s :: %lu success/s.",
    ot_overall_tcp_connections+ot_overall_udp_connections,
    ot_overall_tcp_successfulannounces+ot_overall_udp_successfulannounces,
    (int)t,
    (int)(t / 3600),
    events_per_time( ot_overall_tcp_connections+ot_overall_udp_connections, t ),
    events_per_time( ot_overall_tcp_successfulannounces+ot_overall_udp_successfulannounces, t )
  );
}

static size_t stats_udpconnections_mrtg( char * reply ) {
  ot_time t = time( NULL ) - ot_start_time;
  return sprintf( reply,
    "%llu\n%llu\n%i seconds (%i hours)\nopentracker udp4 stats, %lu conns/s :: %lu success/s.",
    ot_overall_udp_connections,
    ot_overall_udp_successfulannounces,
    (int)t,
    (int)(t / 3600),
    events_per_time( ot_overall_udp_connections, t ),
    events_per_time( ot_overall_udp_successfulannounces, t )
  );
}

static size_t stats_tcpconnections_mrtg( char * reply ) {
  time_t t = time( NULL ) - ot_start_time;
  return sprintf( reply,
    "%llu\n%llu\n%i seconds (%i hours)\nopentracker tcp4 stats, %lu conns/s :: %lu success/s.",
    ot_overall_tcp_connections,
    ot_overall_tcp_successfulannounces,
    (int)t,
    (int)(t / 3600),
    events_per_time( ot_overall_tcp_connections, t ),
    events_per_time( ot_overall_tcp_successfulannounces, t )
  );
}


static size_t stats_fullscrapes_mrtg( char * reply ) {
  ot_time t = time( NULL ) - ot_start_time;
  return sprintf( reply,
    "%llu\n%llu\n%i seconds (%i hours)\nopentracker full scrape stats, %lu conns/s :: %lu bytes/s.",
    ot_full_scrape_count * 1000,
    ot_full_scrape_size,
    (int)t,
    (int)(t / 3600),
    events_per_time( ot_full_scrape_count, t ),
    events_per_time( ot_full_scrape_size, t )
  );
}

static size_t stats_peers_mrtg( char * reply ) {
  size_t    torrent_count = 0, peer_count = 0, seed_count = 0, j;
  int bucket;

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    torrent_count += torrents_list->size;
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      peer_count += peer_list->peer_count; seed_count += peer_list->seed_count;
    }
    mutex_bucket_unlock( bucket );
  }
  return sprintf( reply, "%zd\n%zd\nopentracker serving %zd torrents\nopentracker",
    peer_count,
    seed_count,
    torrent_count
  );
}

size_t return_stats_for_tracker( char *reply, int mode, int format ) {
  format = format;
  switch( mode ) {
    case STATS_CONNS:
      return stats_connections_mrtg( reply );
    case STATS_UDP:
      return stats_udpconnections_mrtg( reply );
    case STATS_TCP:
      return stats_tcpconnections_mrtg( reply );
    case STATS_PEERS:
      return stats_peers_mrtg( reply );
    case STATS_SLASH24S:
      return stats_slash24s_txt( reply, 25, 16 );
    case STATS_TOP5:
      return stats_top5_txt( reply );
    case STATS_FULLSCRAPE:
      return stats_fullscrapes_mrtg( reply );
    default:
      return 0;
  }
}

void stats_issue_event( ot_status_event event, int is_tcp, size_t event_data ) {
  switch( event ) {
    case EVENT_ACCEPT:
      if( is_tcp ) ot_overall_tcp_connections++; else ot_overall_udp_connections++;
      break;
    case EVENT_ANNOUNCE:
      if( is_tcp ) ot_overall_tcp_successfulannounces++; else ot_overall_udp_successfulannounces++;
      break;
    case EVENT_SCRAPE:
      if( is_tcp ) ot_overall_tcp_successfulscrapes++; else ot_overall_udp_successfulscrapes++;
    case EVENT_FULLSCRAPE:
      ot_full_scrape_count++;
      ot_full_scrape_size += event_data;
      break;
    default:
      break;
  }
}
