/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

/* Libowfat */
#include "byte.h"
#include "io.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_iovec.h"
#include "ot_stats.h"

#ifndef NO_FULLSCRAPE_LOGGING
#define LOG_TO_STDERR( ... ) fprintf( stderr, __VA_ARGS__ )
#else
#define LOG_TO_STDERR( ... )
#endif

/* Forward declaration */
static void stats_make( int *iovec_entries, struct iovec **iovector, ot_tasktype mode );
#define OT_STATS_TMPSIZE 8192

/* Clumsy counters... to be rethought */
static unsigned long long ot_overall_tcp_connections = 0;
static unsigned long long ot_overall_udp_connections = 0;
static unsigned long long ot_overall_tcp_successfulannounces = 0;
static unsigned long long ot_overall_udp_successfulannounces = 0;
static unsigned long long ot_overall_tcp_successfulscrapes = 0;
static unsigned long long ot_overall_udp_successfulscrapes = 0;
static unsigned long long ot_overall_tcp_connects = 0;
static unsigned long long ot_overall_udp_connects = 0;
static unsigned long long ot_full_scrape_count = 0;
static unsigned long long ot_full_scrape_request_count = 0;
static unsigned long long ot_full_scrape_size = 0;
static unsigned long long ot_failed_request_counts[CODE_HTTPERROR_COUNT];
static unsigned long long ot_renewed[OT_POOLS_COUNT];

static time_t ot_start_time;

#ifdef WANT_LOG_NETWORKS
#define STATS_NETWORK_NODE_BITWIDTH  8
#define STATS_NETWORK_NODE_MAXDEPTH  3

#define STATS_NETWORK_NODE_BITMASK ((1<<STATS_NETWORK_NODE_BITWIDTH)-1)
#define STATS_NETWORK_NODE_COUNT    (1<<STATS_NETWORK_NODE_BITWIDTH)

typedef union stats_network_node stats_network_node;
union stats_network_node {
  int                 counters[STATS_NETWORK_NODE_COUNT];
  stats_network_node *children[STATS_NETWORK_NODE_COUNT];
};

static stats_network_node *stats_network_counters_root = NULL;

static int stat_increase_network_count( stats_network_node **node, int depth, uint32_t ip ) {
  int foo = ( ip >> ( 32 - STATS_NETWORK_NODE_BITWIDTH * ( ++depth ) ) ) & STATS_NETWORK_NODE_BITMASK;

  if( !*node ) {
    *node = malloc( sizeof( stats_network_node ) );
    if( !*node )
      return -1;
    memset( *node, 0, sizeof( stats_network_node ) );
  }

  if( depth < STATS_NETWORK_NODE_MAXDEPTH )
    return stat_increase_network_count( &(*node)->children[ foo ], depth, ip );

  (*node)->counters[ foo ]++;
  return 0;
}

static int stats_shift_down_network_count( stats_network_node **node, int depth, int shift ) {
  int i, rest = 0;
  if( !*node ) return 0;

  if( ++depth == STATS_NETWORK_NODE_MAXDEPTH )
    for( i=0; i<STATS_NETWORK_NODE_COUNT; ++i ) {
      rest += ((*node)->counters[i]>>=shift);
    return rest;
  }

  for( i=0; i<STATS_NETWORK_NODE_COUNT; ++i ) {
    stats_network_node **childnode = &(*node)->children[i];
    int rest_val;

    if( !*childnode ) continue;

    rest += rest_val = stats_shift_down_network_count( childnode, depth, shift );

    if( rest_val ) continue;

    free( (*node)->children[i] );
    (*node)->children[i] = NULL;
  }

  return rest;
}

static void stats_get_highscore_networks( stats_network_node *node, int depth, uint32_t node_value, int *scores, uint32_t *networks, int network_count ) {
  int i;

  if( !node ) return;

  if( !depth++ ) {
    memset( scores, 0, sizeof( *scores ) * network_count );
    memset( networks, 0, sizeof( *networks ) * network_count );
  }

  if( depth < STATS_NETWORK_NODE_MAXDEPTH ) {
    for( i=0; i<STATS_NETWORK_NODE_COUNT; ++i )
      if( node->children[i] )
        stats_get_highscore_networks( node->children[i], depth, node_value | ( i << ( 32 - depth * STATS_NETWORK_NODE_BITWIDTH ) ), scores, networks, network_count );
  } else
    for( i=0; i<STATS_NETWORK_NODE_COUNT; ++i ) {
      int j=1;
      if( node->counters[i] <= scores[0] ) continue;

      while( (j<network_count) && (node->counters[i]>scores[j] ) ) ++j;
      --j;

      memmove( scores, scores + 1, j * sizeof( *scores ) );
      memmove( networks, networks + 1, j * sizeof( *networks ) );
      scores[ j ] = node->counters[ i ];
      networks[ j ] = node_value | ( i << ( 32 - depth * STATS_NETWORK_NODE_BITWIDTH ) );
  }
}

static size_t stats_return_busy_networks( char * reply ) {
  uint32_t networks[16];
  int      scores[16];
  int      i;
  char   * r = reply;

  stats_get_highscore_networks( stats_network_counters_root, 0, 0, scores, networks, 16 );

  for( i=15; i>=0; --i)
    r += sprintf( r, "%08i: %d.%d.%d.0/24\n", scores[i], (networks[i]>>24)&0xff, (networks[i]>>16)&0xff, (networks[i]>>8)&0xff );

  return r - reply;
}

#endif

/* Converter function from memory to human readable hex strings */
static char*to_hex(char*d,uint8_t*s){char*m="0123456789ABCDEF";char *t=d;char*e=d+40;while(d<e){*d++=m[*s>>4];*d++=m[*s++&15];}*d=0;return t;}

typedef struct { size_t val; ot_torrent * torrent; } ot_record;

/* Fetches stats from tracker */
size_t stats_top10_txt( char * reply ) {
  size_t    j;
  ot_record top10s[10], top10c[10];
  char     *r  = reply, hex_out[42];
  int       idx, bucket;

  byte_zero( top10s, sizeof( top10s ) );
  byte_zero( top10c, sizeof( top10c ) );

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      int idx = 9; while( (idx >= 0) && ( peer_list->peer_count > top10c[idx].val ) ) --idx;
      if ( idx++ != 9 ) {
        memmove( top10c + idx + 1, top10c + idx, ( 9 - idx ) * sizeof( ot_record ) );
        top10c[idx].val = peer_list->peer_count;
        top10c[idx].torrent = (ot_torrent*)(torrents_list->data) + j;
      }
      idx = 9; while( (idx >= 0) && ( peer_list->seed_count > top10s[idx].val ) ) --idx;
      if ( idx++ != 9 ) {
        memmove( top10s + idx + 1, top10s + idx, ( 9 - idx ) * sizeof( ot_record ) );
        top10s[idx].val = peer_list->seed_count;
        top10s[idx].torrent = (ot_torrent*)(torrents_list->data) + j;
      }
    }
    mutex_bucket_unlock( bucket );
  }

  r += sprintf( r, "Top 10 torrents by peers:\n" );
  for( idx=0; idx<10; ++idx )
    if( top10c[idx].torrent )
      r += sprintf( r, "\t%zd\t%s\n", top10c[idx].val, to_hex( hex_out, top10c[idx].torrent->hash) );
  r += sprintf( r, "Top 10 torrents by seeds:\n" );
  for( idx=0; idx<10; ++idx )
    if( top10s[idx].torrent )
      r += sprintf( r, "\t%zd\t%s\n", top10s[idx].val, to_hex( hex_out, top10s[idx].torrent->hash) );

  return r - reply;
}

/* This function collects 4096 /24s in 4096 possible
   malloc blocks
*/
static size_t stats_slash24s_txt( char * reply, size_t amount, uint32_t thresh ) {

#define NUM_TOPBITS 12
#define NUM_LOWBITS (24-NUM_TOPBITS)
#define NUM_BUFS    (1<<NUM_TOPBITS)
#define NUM_S24S    (1<<NUM_LOWBITS)
#define MSK_S24S    (NUM_S24S-1)

  uint32_t *counts[ NUM_BUFS ];
  uint32_t  slash24s[amount*2];  /* first dword amount, second dword subnet */
  int       bucket;
  size_t    i, j, k, l;
  char     *r  = reply;

  byte_zero( counts, sizeof( counts ) );
  byte_zero( slash24s, amount * 2 * sizeof(uint32_t) );

  r += sprintf( r, "Stats for all /24s with more than %u announced torrents:\n\n", thresh );

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      for( k=0; k<OT_POOLS_COUNT; ++k ) {
        ot_peer *peers =    peer_list->peers[k].data;
        size_t   numpeers = peer_list->peers[k].size;
        for( l=0; l<numpeers; ++l ) {
          uint32_t s24 = ntohl(*(uint32_t*)(peers+l)) >> 8;
          uint32_t *count = counts[ s24 >> NUM_LOWBITS ];
          if( !count ) {
            count = malloc( sizeof(uint32_t) * NUM_S24S );
            if( !count ) {
              mutex_bucket_unlock( bucket );
              goto bailout_cleanup;
            }
            byte_zero( count, sizeof( uint32_t ) * NUM_S24S );
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
    uint32_t *count = counts[i];
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
        memmove( slash24s + 2 * ( insert_pos + 1 ), slash24s + 2 * ( insert_pos ), 2 * sizeof( uint32_t ) * ( amount - insert_pos - 1 ) );
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
      uint32_t ip = slash24s[ 2*i +1 ];
      r += sprintf( r, "% 10ld %d.%d.%d.0/24\n", (long)slash24s[ 2*i ], (int)(ip >> 16), (int)(255 & ( ip >> 8 )), (int)(ip & 255) );
    }

  return r - reply;

bailout_cleanup:

  for( i=0; i < NUM_BUFS; ++i )
    free( counts[i] );

  return 0;
}

/*
 struct {
   size_t size
   size_t space
   size_t count
 }
 */

static ssize_t stats_vector_usage( char * reply ) {
  size_t i, j, *vec_member;
  char *r = reply;
  int exactmatch, bucket;

  ot_vector bucketsizes;
  memset( &bucketsizes, 0, sizeof( bucketsizes ));

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    for( i=0; i<torrents_list->size; ++i ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[i] ).peer_list;
      for( j=0; j<OT_POOLS_COUNT; ++j ) {
        if( ! ( vec_member = vector_find_or_insert(&bucketsizes, &peer_list->peers[j].size, 3 * sizeof( size_t ), 2 * sizeof(size_t), &exactmatch) ) ) {
          mutex_bucket_unlock( bucket );
          return 0;
        }
        if( !exactmatch ) {
          vec_member[0] = peer_list->peers[j].size;
          vec_member[1] = peer_list->peers[j].space;
          vec_member[2] = 1;
        } else
          ++vec_member[2];
      }
    }
    mutex_bucket_unlock( bucket );
  }

  for( i = 0; i<bucketsizes.size; ++i ) {
    r += sprintf( r, "%zd\t%zd\t%zd\n", ((size_t*)bucketsizes.data)[3*i], ((size_t*)bucketsizes.data)[3*i+1], ((size_t*)bucketsizes.data)[3*i+2] );
    /* Prevent overflow. 8k should be enough for debugging */
    if( r - reply > OT_STATS_TMPSIZE - 3*10+3 /* 3*%zd + 2*\t + \n */ )
      break;
  }

  return r - reply;
}

static unsigned long events_per_time( unsigned long long events, time_t t ) {
  return events / ( (unsigned int)t ? (unsigned int)t : 1 );
}

static size_t stats_connections_mrtg( char * reply ) {
  ot_time t = time( NULL ) - ot_start_time;
  return sprintf( reply,
    "%llu\n%llu\n%i seconds (%i hours)\nopentracker connections, %lu conns/s :: %lu success/s.",
    ot_overall_tcp_connections+ot_overall_udp_connections,
    ot_overall_tcp_successfulannounces+ot_overall_udp_successfulannounces+ot_overall_udp_connects,
    (int)t,
    (int)(t / 3600),
    events_per_time( ot_overall_tcp_connections+ot_overall_udp_connections, t ),
    events_per_time( ot_overall_tcp_successfulannounces+ot_overall_udp_successfulannounces+ot_overall_udp_connects, t )
  );
}

static size_t stats_udpconnections_mrtg( char * reply ) {
  ot_time t = time( NULL ) - ot_start_time;
  return sprintf( reply,
    "%llu\n%llu\n%i seconds (%i hours)\nopentracker udp4 stats, %lu conns/s :: %lu success/s.",
    ot_overall_udp_connections,
    ot_overall_udp_successfulannounces+ot_overall_udp_connects,
    (int)t,
    (int)(t / 3600),
    events_per_time( ot_overall_udp_connections, t ),
    events_per_time( ot_overall_udp_successfulannounces+ot_overall_udp_connects, t )
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

static size_t stats_scrape_mrtg( char * reply ) {
  time_t t = time( NULL ) - ot_start_time;
  return sprintf( reply,
    "%llu\n%llu\n%i seconds (%i hours)\nopentracker scrape stats, %lu scrape/s (tcp and udp)",
    ot_overall_tcp_successfulscrapes,
    ot_overall_udp_successfulscrapes,
    (int)t,
    (int)(t / 3600),
    events_per_time( (ot_overall_tcp_successfulscrapes+ot_overall_udp_successfulscrapes), t )
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

static size_t stats_startstop_mrtg( char * reply )
{
  size_t    torrent_count = 0;
  int bucket;

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket )
  {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    torrent_count += torrents_list->size;
    mutex_bucket_unlock( bucket );
  }

  return sprintf( reply, "%zd\n%zd\nopentracker handling %zd torrents\nopentracker",
    (size_t)0,
    (size_t)0,
    torrent_count
  );
}

static size_t stats_toraddrem_mrtg( char * reply )
{
  size_t    peer_count = 0, j;
  int bucket;

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket )
  {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    for( j=0; j<torrents_list->size; ++j )
    {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      peer_count += peer_list->peer_count;
    }
    mutex_bucket_unlock( bucket );
  }

  return sprintf( reply, "%zd\n%zd\nopentracker handling %zd peers\nopentracker",
    (size_t)0,
    (size_t)0,
    peer_count
  );
}

static size_t stats_torrents_mrtg( char * reply )
{
  size_t torrent_count = 0;
  int bucket;

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket )
  {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    torrent_count += torrents_list->size;
    mutex_bucket_unlock( bucket );
  }

  return sprintf( reply, "%zd\n%zd\nopentracker serving %zd torrents\nopentracker",
    torrent_count,
    (size_t)0,
    torrent_count
  );
}

static size_t stats_httperrors_txt ( char * reply ) {
  return sprintf( reply, "302 RED %llu\n400 ... %llu\n400 PAR %llu\n400 COM %llu\n403 IP  %llu\n404 INV %llu\n500 SRV %llu\n",
  ot_failed_request_counts[0], ot_failed_request_counts[1], ot_failed_request_counts[2],
  ot_failed_request_counts[3], ot_failed_request_counts[4], ot_failed_request_counts[5],
  ot_failed_request_counts[6] );
}

static size_t stats_return_renew_bucket( char * reply ) {
  char *r = reply;
  int i;

  for( i=0; i<OT_POOLS_COUNT; ++i )
    r+=sprintf(r,"%02i %llu\n", i, ot_renewed[i] );
  return r - reply;
}

extern const char
*g_version_opentracker_c, *g_version_accesslist_c, *g_version_clean_c, *g_version_fullscrape_c, *g_version_http_c,
*g_version_iovec_c, *g_version_mutex_c, *g_version_stats_c, *g_version_sync_c, *g_version_udp_c, *g_version_vector_c,
*g_version_scan_urlencoded_query_c, *g_version_trackerlogic_c, *g_version_livesync_c;

size_t stats_return_tracker_version( char *reply ) {
  return sprintf( reply, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
  g_version_opentracker_c, g_version_accesslist_c, g_version_clean_c, g_version_fullscrape_c, g_version_http_c,
  g_version_iovec_c, g_version_mutex_c, g_version_stats_c, g_version_sync_c, g_version_udp_c, g_version_vector_c,
  g_version_scan_urlencoded_query_c, g_version_trackerlogic_c, g_version_livesync_c );
}

size_t return_stats_for_tracker( char *reply, int mode, int format ) {
  format = format;
  switch( mode & TASK_TASK_MASK ) {
    case TASK_STATS_CONNS:
      return stats_connections_mrtg( reply );
    case TASK_STATS_SCRAPE:
      return stats_scrape_mrtg( reply );
    case TASK_STATS_UDP:
      return stats_udpconnections_mrtg( reply );
    case TASK_STATS_TCP:
      return stats_tcpconnections_mrtg( reply );
    case TASK_STATS_TORADDREM:
      return stats_toraddrem_mrtg( reply );
    case TASK_STATS_STARTSTOP:
      return stats_startstop_mrtg( reply );
    case TASK_STATS_FULLSCRAPE:
      return stats_fullscrapes_mrtg( reply );
    case TASK_STATS_HTTPERRORS:
      return stats_httperrors_txt( reply );
    case TASK_STATS_VERSION:
      return stats_return_tracker_version( reply );
    case TASK_STATS_RENEW:
      return stats_return_renew_bucket( reply );
#ifdef WANT_LOG_NETWORKS
    case TASK_STATS_BUSY_NETWORKS:
      return stats_return_busy_networks( reply );
#endif
#ifdef _DEBUG_VECTOR
    case TASK_STATS_VECTOR_DEBUG:
      return vector_info( reply );
#endif
    default:
      return 0;
  }
}

static void stats_make( int *iovec_entries, struct iovec **iovector, ot_tasktype mode ) {
  char *r;

  *iovec_entries = 0;
  *iovector      = NULL;
  if( !( r = iovec_increase( iovec_entries, iovector, OT_STATS_TMPSIZE ) ) )
    return;

  switch( mode & TASK_TASK_MASK ) {
    case TASK_STATS_TORRENTS:    r += stats_torrents_mrtg( r );             break;
    case TASK_STATS_PEERS:       r += stats_peers_mrtg( r );                break;
    case TASK_STATS_SLASH24S:    r += stats_slash24s_txt( r, 25, 16 );      break;
    case TASK_STATS_TOP10:       r += stats_top10_txt( r );                 break;
    case TASK_STATS_MEMORY:      r += stats_vector_usage( r );              break;
    default:
      iovec_free(iovec_entries, iovector);
      return;
  }
  iovec_fixlast( iovec_entries, iovector, r );
}

void stats_issue_event( ot_status_event event, PROTO_FLAG proto, uint32_t event_data ) {
  switch( event ) {
    case EVENT_ACCEPT:
      if( proto == FLAG_TCP ) ot_overall_tcp_connections++; else ot_overall_udp_connections++;
#ifdef WANT_LOG_NETWORKS
      stat_increase_network_count( &stats_network_counters_root, 0, event_data );
#endif
      break;
    case EVENT_ANNOUNCE:
      if( proto == FLAG_TCP ) ot_overall_tcp_successfulannounces++; else ot_overall_udp_successfulannounces++;
      break;
   case EVENT_CONNECT:
      if( proto == FLAG_TCP ) ot_overall_tcp_connects++; else ot_overall_udp_connects++;
      break;
    case EVENT_SCRAPE:
      if( proto == FLAG_TCP ) ot_overall_tcp_successfulscrapes++; else ot_overall_udp_successfulscrapes++;
    case EVENT_FULLSCRAPE:
      ot_full_scrape_count++;
      ot_full_scrape_size += event_data;
      break;
    case EVENT_FULLSCRAPE_REQUEST:
      {
      uint8_t ip[4]; *(uint32_t*)ip = (uint32_t)proto; /* ugly hack to transfer ip to stats */
      LOG_TO_STDERR( "[%08d] scrp: %d.%d.%d.%d - FULL SCRAPE\n", (unsigned int)(g_now - ot_start_time), ip[0], ip[1], ip[2], ip[3] );
      ot_full_scrape_request_count++;
      }
      break;
    case EVENT_FULLSCRAPE_REQUEST_GZIP:
      {
      uint8_t ip[4]; *(uint32_t*)ip = (uint32_t)proto; /* ugly hack to transfer ip to stats */
      LOG_TO_STDERR( "[%08d] scrp: %d.%d.%d.%d - FULL SCRAPE GZIP\n", (unsigned int)(g_now - ot_start_time), ip[0], ip[1], ip[2], ip[3] );
      ot_full_scrape_request_count++;
      }
      break;
    case EVENT_FAILED:
      ot_failed_request_counts[event_data]++;
      break;
    case EVENT_RENEW:
      ot_renewed[event_data]++;
      break;
    case EVENT_SYNC_IN_REQUEST:
    case EVENT_SYNC_IN:
    case EVENT_SYNC_OUT_REQUEST:
    case EVENT_SYNC_OUT:
      break;
    default:
      break;
  }
}

static void * stats_worker( void * args ) {
  int iovec_entries;
  struct iovec *iovector;

  args = args;

  while( 1 ) {
    ot_tasktype tasktype = TASK_STATS;
    ot_taskid   taskid   = mutex_workqueue_poptask( &tasktype );
    stats_make( &iovec_entries, &iovector, tasktype );
    if( mutex_workqueue_pushresult( taskid, iovec_entries, iovector ) )
      iovec_free( &iovec_entries, &iovector );
  }
  return NULL;
}

void stats_deliver( int64 socket, int tasktype ) {
  mutex_workqueue_pushtask( socket, tasktype );
}

static pthread_t thread_id;
void stats_init( ) {
  ot_start_time = g_now;
  pthread_create( &thread_id, NULL, stats_worker, NULL );
}

void stats_deinit( ) {
  pthread_cancel( thread_id );
}

const char *g_version_stats_c = "$Source$: $Revision$\n";
