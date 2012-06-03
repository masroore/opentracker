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
#include <unistd.h>
#include <inttypes.h>
#ifdef WANT_SYSLOGS
#include <syslog.h>
#endif

/* Libowfat */
#include "byte.h"
#include "io.h"
#include "ip4.h"
#include "ip6.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_iovec.h"
#include "ot_stats.h"
#include "ot_accesslist.h"

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
static unsigned long long ot_overall_udp_connectionidmissmatches = 0;
static unsigned long long ot_overall_tcp_connects = 0;
static unsigned long long ot_overall_udp_connects = 0;
static unsigned long long ot_overall_completed = 0;
static unsigned long long ot_full_scrape_count = 0;
static unsigned long long ot_full_scrape_request_count = 0;
static unsigned long long ot_full_scrape_size = 0;
static unsigned long long ot_failed_request_counts[CODE_HTTPERROR_COUNT];
static char *             ot_failed_request_names[] = { "302 Redirect", "400 Parse Error", "400 Invalid Parameter", "400 Invalid Parameter (compact=0)", "400 Not Modest", "403 Access Denied", "404 Not found", "500 Internal Server Error" };
static unsigned long long ot_renewed[OT_PEER_TIMEOUT];
static unsigned long long ot_overall_sync_count;
static unsigned long long ot_overall_stall_count;

static time_t ot_start_time;

#define STATS_NETWORK_NODE_BITWIDTH       4
#define STATS_NETWORK_NODE_COUNT         (1<<STATS_NETWORK_NODE_BITWIDTH)

#define __BYTE(P,D)  (((uint8_t*)P)[D/8])
#define __MSK        (STATS_NETWORK_NODE_COUNT-1)
#define __SHFT(D)    ((D^STATS_NETWORK_NODE_BITWIDTH)&STATS_NETWORK_NODE_BITWIDTH)

#define __LDR(P,D)   ((__BYTE((P),(D))>>__SHFT((D)))&__MSK)
#define __STR(P,D,V)   __BYTE((P),(D))=(__BYTE((P),(D))&~(__MSK<<__SHFT((D))))|((V)<<__SHFT((D)))

#ifdef WANT_V6
#define STATS_NETWORK_NODE_MAXDEPTH  (68-STATS_NETWORK_NODE_BITWIDTH)
#define STATS_NETWORK_NODE_LIMIT     (48-STATS_NETWORK_NODE_BITWIDTH)
#else
#define STATS_NETWORK_NODE_MAXDEPTH  (28-STATS_NETWORK_NODE_BITWIDTH)
#define STATS_NETWORK_NODE_LIMIT     (24-STATS_NETWORK_NODE_BITWIDTH)
#endif

typedef union stats_network_node stats_network_node;
union stats_network_node {
  size_t              counters[STATS_NETWORK_NODE_COUNT];
  stats_network_node *children[STATS_NETWORK_NODE_COUNT];
};

#ifdef WANT_LOG_NETWORKS
static stats_network_node *stats_network_counters_root;
#endif

static int stat_increase_network_count( stats_network_node **pnode, int depth, uintptr_t ip ) {
  int foo = __LDR(ip,depth);
  stats_network_node *node;

  if( !*pnode ) {
    *pnode = malloc( sizeof( stats_network_node ) );
    if( !*pnode )
      return -1;
    memset( *pnode, 0, sizeof( stats_network_node ) );
  }
  node = *pnode;

  if( depth < STATS_NETWORK_NODE_MAXDEPTH )
    return stat_increase_network_count( node->children + foo, depth+STATS_NETWORK_NODE_BITWIDTH, ip );

  node->counters[ foo ]++;
  return 0;
}

static int stats_shift_down_network_count( stats_network_node **node, int depth, int shift ) {
  int i, rest = 0;

  if( !*node )
    return 0;

  for( i=0; i<STATS_NETWORK_NODE_COUNT; ++i )
    if( depth < STATS_NETWORK_NODE_MAXDEPTH )
      rest += stats_shift_down_network_count( (*node)->children + i, depth+STATS_NETWORK_NODE_BITWIDTH, shift );
    else
      rest += (*node)->counters[i] >>= shift;

  if( !rest ) {
    free( *node );
    *node = NULL;
  }

  return rest;
}

static size_t stats_get_highscore_networks( stats_network_node *node, int depth, ot_ip6 node_value, size_t *scores, ot_ip6 *networks, int network_count, int limit ) {
  size_t score = 0;
  int i;

  if( !node ) return 0;

  if( depth < limit ) {
    for( i=0; i<STATS_NETWORK_NODE_COUNT; ++i )
      if( node->children[i] ) {
        __STR(node_value,depth,i);
        score += stats_get_highscore_networks( node->children[i], depth+STATS_NETWORK_NODE_BITWIDTH, node_value, scores, networks, network_count, limit );
      }
    return score;
  }

  if( depth > limit && depth < STATS_NETWORK_NODE_MAXDEPTH ) {
    for( i=0; i<STATS_NETWORK_NODE_COUNT; ++i )
      if( node->children[i] )
        score += stats_get_highscore_networks( node->children[i], depth+STATS_NETWORK_NODE_BITWIDTH, node_value, scores, networks, network_count, limit );
    return score;
  }

  if( depth > limit && depth == STATS_NETWORK_NODE_MAXDEPTH ) {
    for( i=0; i<STATS_NETWORK_NODE_COUNT; ++i )
      score += node->counters[i];
    return score;
  }

  /* if( depth == limit ) */
  for( i=0; i<STATS_NETWORK_NODE_COUNT; ++i ) {
    int j=1;
    size_t node_score;

    if( depth == STATS_NETWORK_NODE_MAXDEPTH )
      node_score = node->counters[i];
    else
      node_score = stats_get_highscore_networks( node->children[i], depth+STATS_NETWORK_NODE_BITWIDTH, node_value, scores, networks, network_count, limit );

    score += node_score;

    if( node_score <= scores[0] ) continue;

    __STR(node_value,depth,i);
    while( j < network_count && node_score > scores[j] ) ++j;
    --j;

    memcpy( scores, scores + 1, j * sizeof( *scores ) );
    memcpy( networks, networks + 1, j * sizeof( *networks ) );
    scores[ j ] = node_score;
    memcpy( networks + j, node_value, sizeof( *networks ) );
  }

  return score;
}

static size_t stats_return_busy_networks( char * reply, stats_network_node *tree, int amount, int limit ) {
  ot_ip6   networks[amount];
  ot_ip6   node_value;
  size_t   scores[amount];
  int      i;
  char   * r = reply;

  memset( scores, 0, sizeof( scores ) );
  memset( networks, 0, sizeof( networks ) );
  memset( node_value, 0, sizeof( node_value ) );

  stats_get_highscore_networks( tree, 0, node_value, scores, networks, amount, limit );

  r += sprintf( r, "Networks, limit /%d:\n", limit+STATS_NETWORK_NODE_BITWIDTH );
  for( i=amount-1; i>=0; --i) {
    if( scores[i] ) {
      r += sprintf( r, "%08zd: ", scores[i] );
#ifdef WANT_V6
      r += fmt_ip6c( r, networks[i] );
#else
      r += fmt_ip4( r, networks[i]);
#endif
      *r++ = '\n';
    }
  }
  *r++ = '\n';

  return r - reply;
}

static size_t stats_slash24s_txt( char *reply, size_t amount ) {
  stats_network_node *slash24s_network_counters_root = NULL;
  char *r=reply;
  int bucket;
  size_t i;

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    for( i=0; i<torrents_list->size; ++i ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[i] ).peer_list;
      ot_vector   *bucket_list = &peer_list->peers;
      int          num_buckets = 1;

      if( OT_PEERLIST_HASBUCKETS( peer_list ) ) {
        num_buckets = bucket_list->size;
        bucket_list = (ot_vector *)bucket_list->data;
      }

      while( num_buckets-- ) {
        ot_peer *peers = (ot_peer*)bucket_list->data;
        size_t   numpeers = bucket_list->size;
        while( numpeers-- )
          if( stat_increase_network_count( &slash24s_network_counters_root, 0, (uintptr_t)(peers++) ) )
            goto bailout_unlock;
        ++bucket_list;
      }
    }
    mutex_bucket_unlock( bucket, 0 );
    if( !g_opentracker_running )
      goto bailout_error;
  }

  /* The tree is built. Now analyze */
  r += stats_return_busy_networks( r, slash24s_network_counters_root, amount, STATS_NETWORK_NODE_MAXDEPTH );
  r += stats_return_busy_networks( r, slash24s_network_counters_root, amount, STATS_NETWORK_NODE_LIMIT );
  goto success;

bailout_unlock:
  mutex_bucket_unlock( bucket, 0 );
bailout_error:
  r = reply;
success:
  stats_shift_down_network_count( &slash24s_network_counters_root, 0, sizeof(int)*8-1 );

  return r-reply;
}

#ifdef WANT_SPOT_WOODPECKER
static stats_network_node *stats_woodpeckers_tree;
static pthread_mutex_t g_woodpeckers_mutex = PTHREAD_MUTEX_INITIALIZER;

static size_t stats_return_woodpeckers( char * reply, int amount ) {
  char * r = reply;

  pthread_mutex_lock( &g_woodpeckers_mutex );
  r += stats_return_busy_networks( r, stats_woodpeckers_tree, amount, STATS_NETWORK_NODE_MAXDEPTH );
  pthread_mutex_unlock( &g_woodpeckers_mutex );
  return r-reply;
}
#endif

typedef struct {
  unsigned long long torrent_count;
  unsigned long long peer_count;
  unsigned long long seed_count;
} torrent_stats;

static int torrent_statter( ot_torrent *torrent, uintptr_t data ) {
  torrent_stats *stats = (torrent_stats*)data;
  stats->torrent_count++;
  stats->peer_count += torrent->peer_list->peer_count;
  stats->seed_count += torrent->peer_list->seed_count;
  return 0;
}

/* Converter function from memory to human readable hex strings */
static char*to_hex(char*d,uint8_t*s){char*m="0123456789ABCDEF";char *t=d;char*e=d+40;while(d<e){*d++=m[*s>>4];*d++=m[*s++&15];}*d=0;return t;}

typedef struct { size_t val; ot_torrent * torrent; } ot_record;

/* Fetches stats from tracker */
size_t stats_top_txt( char * reply, int amount ) {
  size_t    j;
  ot_record top100s[100], top100c[100];
  char     *r  = reply, hex_out[42];
  int       idx, bucket;

  if( amount > 100 )
    amount = 100;

  byte_zero( top100s, sizeof( top100s ) );
  byte_zero( top100c, sizeof( top100c ) );

  for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
    ot_vector *torrents_list = mutex_bucket_lock( bucket );
    for( j=0; j<torrents_list->size; ++j ) {
      ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[j] ).peer_list;
      int idx = amount - 1; while( (idx >= 0) && ( peer_list->peer_count > top100c[idx].val ) ) --idx;
      if ( idx++ != amount - 1 ) {
        memmove( top100c + idx + 1, top100c + idx, ( amount - 1 - idx ) * sizeof( ot_record ) );
        top100c[idx].val = peer_list->peer_count;
        top100c[idx].torrent = (ot_torrent*)(torrents_list->data) + j;
      }
      idx = amount - 1; while( (idx >= 0) && ( peer_list->seed_count > top100s[idx].val ) ) --idx;
      if ( idx++ != amount - 1 ) {
        memmove( top100s + idx + 1, top100s + idx, ( amount - 1 - idx ) * sizeof( ot_record ) );
        top100s[idx].val = peer_list->seed_count;
        top100s[idx].torrent = (ot_torrent*)(torrents_list->data) + j;
      }
    }
    mutex_bucket_unlock( bucket, 0 );
    if( !g_opentracker_running )
      return 0;
  }

  r += sprintf( r, "Top %d torrents by peers:\n", amount );
  for( idx=0; idx<amount; ++idx )
    if( top100c[idx].torrent )
      r += sprintf( r, "\t%zd\t%s\n", top100c[idx].val, to_hex( hex_out, top100c[idx].torrent->hash) );
  r += sprintf( r, "Top %d torrents by seeds:\n", amount );
  for( idx=0; idx<amount; ++idx )
    if( top100s[idx].torrent )
      r += sprintf( r, "\t%zd\t%s\n", top100s[idx].val, to_hex( hex_out, top100s[idx].torrent->hash) );

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
  torrent_stats stats = {0,0,0};

  iterate_all_torrents( torrent_statter, (uintptr_t)&stats );

  return sprintf( reply, "%llu\n%llu\nopentracker serving %llu torrents\nopentracker",
                 stats.peer_count,
                 stats.seed_count,
                 stats.torrent_count
                 );
}

static size_t stats_torrents_mrtg( char * reply )
{
  size_t torrent_count = mutex_get_torrent_count();

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

  for( i=0; i<OT_PEER_TIMEOUT; ++i )
    r+=sprintf(r,"%02i %llu\n", i, ot_renewed[i] );
  return r - reply;
}

static size_t stats_return_sync_mrtg( char * reply ) {
	ot_time t = time( NULL ) - ot_start_time;
	return sprintf( reply,
                 "%llu\n%llu\n%i seconds (%i hours)\nopentracker connections, %lu conns/s :: %lu success/s.",
                 ot_overall_sync_count,
                 0LL,
                 (int)t,
                 (int)(t / 3600),
                 events_per_time( ot_overall_tcp_connections+ot_overall_udp_connections, t ),
                 events_per_time( ot_overall_tcp_successfulannounces+ot_overall_udp_successfulannounces+ot_overall_udp_connects, t )
                 );
}

static size_t stats_return_completed_mrtg( char * reply ) {
  ot_time t = time( NULL ) - ot_start_time;

  return sprintf( reply,
                 "%llu\n%llu\n%i seconds (%i hours)\nopentracker, %lu completed/h.",
                 ot_overall_completed,
                 0LL,
                 (int)t,
                 (int)(t / 3600),
                 events_per_time( ot_overall_completed, t / 3600 )
                 );
}

#ifdef WANT_LOG_NUMWANT
extern unsigned long long numwants[201];
static size_t stats_return_numwants( char * reply ) {
  char * r = reply;
  int i;
  for( i=0; i<=200; ++i )
    r += sprintf( r, "%03d => %lld\n", i, numwants[i] );
  return r-reply;
}
#endif

#ifdef WANT_FULLLOG_NETWORKS
static void stats_return_fulllog( int *iovec_entries, struct iovec **iovector, char *r ) {
  ot_log *loglist = g_logchain_first, *llnext;
  char * re = r + OT_STATS_TMPSIZE;

  g_logchain_first = g_logchain_last = 0;
  
  while( loglist ) {
    if( r + ( loglist->size + 64 ) >= re ) {
      r = iovec_fix_increase_or_free( iovec_entries, iovector, r, 32 * OT_STATS_TMPSIZE );
      if( !r ) return;
      re = r + 32 * OT_STATS_TMPSIZE;
    }
    r += sprintf( r, "%08ld: ", loglist->time );
    r += fmt_ip6c( r, loglist->ip );
    *r++ = '\n';
    memcpy( r, loglist->data, loglist->size );
    r += loglist->size;
    *r++ = '\n';
    *r++ = '*';
    *r++ = '\n';
    *r++ = '\n';

    llnext = loglist->next;
    free( loglist->data );
    free( loglist );
    loglist = llnext;
  }
  iovec_fixlast( iovec_entries, iovector, r );
}
#endif

static size_t stats_return_everything( char * reply ) {
  torrent_stats stats = {0,0,0};
  int i;
  char * r = reply;

  iterate_all_torrents( torrent_statter, (uintptr_t)&stats );

  r += sprintf( r, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" );
  r += sprintf( r, "<stats>\n" );
  r += sprintf( r, "  <tracker_id>%" PRIu32 "</tracker_id>\n", g_tracker_id );
  r += sprintf( r, "  <version>\n" ); r += stats_return_tracker_version( r );  r += sprintf( r, "  </version>\n" );
  r += sprintf( r, "  <uptime>%llu</uptime>\n", (unsigned long long)(time( NULL ) - ot_start_time) );
  r += sprintf( r, "  <torrents>\n" );
  r += sprintf( r, "    <count_mutex>%zd</count_mutex>\n", mutex_get_torrent_count() );
  r += sprintf( r, "    <count_iterator>%llu</count_iterator>\n", stats.torrent_count );
  r += sprintf( r, "  </torrents>\n" );
  r += sprintf( r, "  <peers>\n    <count>%llu</count>\n  </peers>\n", stats.peer_count );
  r += sprintf( r, "  <seeds>\n    <count>%llu</count>\n  </seeds>\n", stats.seed_count );
  r += sprintf( r, "  <completed>\n    <count>%llu</count>\n  </completed>\n", ot_overall_completed );
  r += sprintf( r, "  <connections>\n" );
  r += sprintf( r, "    <tcp>\n      <accept>%llu</accept>\n      <announce>%llu</announce>\n      <scrape>%llu</scrape>\n    </tcp>\n", ot_overall_tcp_connections, ot_overall_tcp_successfulannounces, ot_overall_udp_successfulscrapes );
  r += sprintf( r, "    <udp>\n      <overall>%llu</overall>\n      <connect>%llu</connect>\n      <announce>%llu</announce>\n      <scrape>%llu</scrape>\n      <missmatch>%llu</missmatch>\n    </udp>\n", ot_overall_udp_connections, ot_overall_udp_connects, ot_overall_udp_successfulannounces, ot_overall_udp_successfulscrapes, ot_overall_udp_connectionidmissmatches );
  r += sprintf( r, "    <livesync>\n      <count>%llu</count>\n    </livesync>\n", ot_overall_sync_count );
  r += sprintf( r, "  </connections>\n" );
  r += sprintf( r, "  <debug>\n" );
  r += sprintf( r, "    <renew>\n" );
  for( i=0; i<OT_PEER_TIMEOUT; ++i )
    r += sprintf( r, "      <count interval=\"%02i\">%llu</count>\n", i, ot_renewed[i] );
  r += sprintf( r, "    </renew>\n" );
  r += sprintf( r, "    <http_error>\n" );
  for( i=0; i<CODE_HTTPERROR_COUNT; ++i )
    r += sprintf( r, "      <count code=\"%s\">%llu</count>\n", ot_failed_request_names[i], ot_failed_request_counts[i] );
  r += sprintf( r, "    </http_error>\n" );
  r += sprintf( r, "    <mutex_stall>\n      <count>%llu</count>\n    </mutex_stall>\n", ot_overall_stall_count );
  r += sprintf( r, "  </debug>\n" );
  r += sprintf( r, "</stats>" );
  return r - reply;
}

extern const char
*g_version_opentracker_c, *g_version_accesslist_c, *g_version_clean_c, *g_version_fullscrape_c, *g_version_http_c,
*g_version_iovec_c, *g_version_mutex_c, *g_version_stats_c, *g_version_udp_c, *g_version_vector_c,
*g_version_scan_urlencoded_query_c, *g_version_trackerlogic_c, *g_version_livesync_c, *g_version_rijndael_c;

size_t stats_return_tracker_version( char *reply ) {
  return sprintf( reply, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                 g_version_opentracker_c, g_version_accesslist_c, g_version_clean_c, g_version_fullscrape_c, g_version_http_c,
                 g_version_iovec_c, g_version_mutex_c, g_version_stats_c, g_version_udp_c, g_version_vector_c,
                 g_version_scan_urlencoded_query_c, g_version_trackerlogic_c, g_version_livesync_c, g_version_rijndael_c );
}

size_t return_stats_for_tracker( char *reply, int mode, int format ) {
  (void) format;
  switch( mode & TASK_TASK_MASK ) {
    case TASK_STATS_CONNS:
      return stats_connections_mrtg( reply );
    case TASK_STATS_SCRAPE:
      return stats_scrape_mrtg( reply );
    case TASK_STATS_UDP:
      return stats_udpconnections_mrtg( reply );
    case TASK_STATS_TCP:
      return stats_tcpconnections_mrtg( reply );
    case TASK_STATS_FULLSCRAPE:
      return stats_fullscrapes_mrtg( reply );
    case TASK_STATS_COMPLETED:
      return stats_return_completed_mrtg( reply );
    case TASK_STATS_HTTPERRORS:
      return stats_httperrors_txt( reply );
    case TASK_STATS_VERSION:
      return stats_return_tracker_version( reply );
    case TASK_STATS_RENEW:
      return stats_return_renew_bucket( reply );
    case TASK_STATS_SYNCS:
      return stats_return_sync_mrtg( reply );
#ifdef WANT_LOG_NUMWANT
    case TASK_STATS_NUMWANTS:
      return stats_return_numwants( reply );
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
    case TASK_STATS_SLASH24S:    r += stats_slash24s_txt( r, 128 );         break;
    case TASK_STATS_TOP10:       r += stats_top_txt( r, 10 );               break;
    case TASK_STATS_TOP100:
                                 r = iovec_fix_increase_or_free( iovec_entries, iovector, r, 4 * OT_STATS_TMPSIZE );
                                 if( !r ) return;
                                 r += stats_top_txt( r, 100 );              break;
    case TASK_STATS_EVERYTHING:  r += stats_return_everything( r );         break;
#ifdef WANT_SPOT_WOODPECKER
    case TASK_STATS_WOODPECKERS: r += stats_return_woodpeckers( r, 128 );   break;
#endif
#ifdef WANT_FULLLOG_NETWORKS
    case TASK_STATS_FULLLOG:      stats_return_fulllog( iovec_entries, iovector, r );
                                                                            return;
#endif
    default:
      iovec_free(iovec_entries, iovector);
      return;
  }
  iovec_fixlast( iovec_entries, iovector, r );
}

void stats_issue_event( ot_status_event event, PROTO_FLAG proto, uintptr_t event_data ) {
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
    case EVENT_COMPLETED:
#ifdef WANT_SYSLOGS
      if( event_data) {
        struct ot_workstruct *ws = (struct ot_workstruct *)event_data;
        char timestring[64];
        char hash_hex[42], peerid_hex[42], ip_readable[64];
        struct tm time_now;
        time_t ttt;

        time( &ttt );
        localtime_r( &ttt, &time_now );
        strftime( timestring, sizeof( timestring ), "%FT%T%z", &time_now );

        to_hex( hash_hex, *ws->hash );
        if( ws->peer_id )
          to_hex( peerid_hex, (uint8_t*)ws->peer_id );
        else {
          *peerid_hex=0;
        }

#ifdef WANT_V6
        ip_readable[ fmt_ip6c( ip_readable, (char*)&ws->peer ) ] = 0;
#else
        ip_readable[ fmt_ip4( ip_readable, (char*)&ws->peer ) ] = 0;
#endif
        syslog( LOG_INFO, "time=%s event=completed info_hash=%s peer_id=%s ip=%s", timestring, hash_hex, peerid_hex, ip_readable );
      }
#endif
      ot_overall_completed++;
      break;
    case EVENT_SCRAPE:
      if( proto == FLAG_TCP ) ot_overall_tcp_successfulscrapes++; else ot_overall_udp_successfulscrapes++;
    case EVENT_FULLSCRAPE:
      ot_full_scrape_count++;
      ot_full_scrape_size += event_data;
      break;
    case EVENT_FULLSCRAPE_REQUEST:
    {
      ot_ip6 *ip = (ot_ip6*)event_data; /* ugly hack to transfer ip to stats */
      char _debug[512];
      int off = snprintf( _debug, sizeof(_debug), "[%08d] scrp:  ", (unsigned int)(g_now_seconds - ot_start_time)/60 );
      off += fmt_ip6c( _debug+off, *ip );
      off += snprintf( _debug+off, sizeof(_debug)-off, " - FULL SCRAPE\n" );
      write( 2, _debug, off );
      ot_full_scrape_request_count++;
    }
      break;
    case EVENT_FULLSCRAPE_REQUEST_GZIP:
    {
      ot_ip6 *ip = (ot_ip6*)event_data; /* ugly hack to transfer ip to stats */
      char _debug[512];
      int off = snprintf( _debug, sizeof(_debug), "[%08d] scrp:  ", (unsigned int)(g_now_seconds - ot_start_time)/60 );
      off += fmt_ip6c(_debug+off, *ip );
      off += snprintf( _debug+off, sizeof(_debug)-off, " - FULL SCRAPE\n" );
      write( 2, _debug, off );
      ot_full_scrape_request_count++;
    }
      break;
    case EVENT_FAILED:
      ot_failed_request_counts[event_data]++;
      break;
    case EVENT_RENEW:
      ot_renewed[event_data]++;
      break;
    case EVENT_SYNC:
      ot_overall_sync_count+=event_data;
	    break;
    case EVENT_BUCKET_LOCKED:
      ot_overall_stall_count++;
      break;
#ifdef WANT_SPOT_WOODPECKER
    case EVENT_WOODPECKER:
      pthread_mutex_lock( &g_woodpeckers_mutex );
      stat_increase_network_count( &stats_woodpeckers_tree, 0, event_data );
      pthread_mutex_unlock( &g_woodpeckers_mutex );
      break;
#endif
    case EVENT_CONNID_MISSMATCH:
      ++ot_overall_udp_connectionidmissmatches;
    default:
      break;
  }
}

void stats_cleanup() {
#ifdef WANT_SPOT_WOODPECKER
  pthread_mutex_lock( &g_woodpeckers_mutex );
  stats_shift_down_network_count( &stats_woodpeckers_tree, 0, 1 );
  pthread_mutex_unlock( &g_woodpeckers_mutex );
#endif
}

static void * stats_worker( void * args ) {
  int iovec_entries;
  struct iovec *iovector;

  (void) args;

  while( 1 ) {
    ot_tasktype tasktype = TASK_STATS;
    ot_taskid   taskid   = mutex_workqueue_poptask( &tasktype );
    stats_make( &iovec_entries, &iovector, tasktype );
    if( mutex_workqueue_pushresult( taskid, iovec_entries, iovector ) )
      iovec_free( &iovec_entries, &iovector );
  }
  return NULL;
}

void stats_deliver( int64 sock, int tasktype ) {
  mutex_workqueue_pushtask( sock, tasktype );
}

static pthread_t thread_id;
void stats_init( ) {
  ot_start_time = g_now_seconds;
  pthread_create( &thread_id, NULL, stats_worker, NULL );
}

void stats_deinit( ) {
  pthread_cancel( thread_id );
}

const char *g_version_stats_c = "$Source$: $Revision$\n";
