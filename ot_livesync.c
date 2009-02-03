/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
 It is considered beerware. Prost. Skol. Cheers or whatever.

 $id$ */

/* System */
#include <sys/types.h>
#include <sys/uio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

/* Libowfat */
#include "socket.h"
#include "ndelay.h"
#include "byte.h"
#include "ip6.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_livesync.h"
#include "ot_accesslist.h"
#include "ot_stats.h"
#include "ot_mutex.h"

#ifdef WANT_SYNC_LIVE

char groupip_1[4] = { 224,0,23,5 };

#define LIVESYNC_INCOMING_BUFFSIZE          (256*256)

#define LIVESYNC_OUTGOING_BUFFSIZE_PEERS     1480
#define LIVESYNC_OUTGOING_WATERMARK_PEERS   (sizeof(ot_peer)+sizeof(ot_hash))

#ifdef WANT_SYNC_SCRAPE
#define LIVESYNC_OUTGOING_BUFFSIZE_SCRAPE    1504
#define LIVESYNC_OUTGOING_WATERMARK_SCRAPE  (sizeof(ot_hash)+sizeof(uint64_t)+sizeof(uint32_t))
#define LIVESYNC_OUTGOING_MAXPACKETS_SCRAPE  100

#define LIVESYNC_FIRST_BEACON_DELAY          (30*60) /* seconds */
#define LIVESYNC_BEACON_INTERVAL             60      /* seconds */
#define LIVESYNC_INQUIRE_THRESH              0.75
#endif /* WANT_SYNC_SCRAPE */

#define LIVESYNC_MAXDELAY                    15      /* seconds */

enum { OT_SYNC_PEER
#ifdef WANT_SYNC_SCRAPE
  , OT_SYNC_SCRAPE_BEACON, OT_SYNC_SCRAPE_INQUIRE, OT_SYNC_SCRAPE_TELL
#endif
};

/* Forward declaration */
static void * livesync_worker( void * args );

/* For outgoing packets */
static int64    g_socket_in = -1;

/* For incoming packets */
static int64    g_socket_out = -1;
static uint8_t  g_inbuffer[LIVESYNC_INCOMING_BUFFSIZE];

static uint8_t  g_peerbuffer_start[LIVESYNC_OUTGOING_BUFFSIZE_PEERS];
static uint8_t *g_peerbuffer_pos;
static uint8_t *g_peerbuffer_highwater = g_peerbuffer_start + LIVESYNC_OUTGOING_BUFFSIZE_PEERS - LIVESYNC_OUTGOING_WATERMARK_PEERS;

static ot_time  g_next_packet_time;

#ifdef WANT_SYNC_SCRAPE
/* Live sync scrape buffers, states and timers */
static ot_time  g_next_beacon_time;
static ot_time  g_next_inquire_time;

static uint8_t  g_scrapebuffer_start[LIVESYNC_OUTGOING_BUFFSIZE_SCRAPE];
static uint8_t *g_scrapebuffer_pos;
static uint8_t *g_scrapebuffer_highwater = g_scrapebuffer_start + LIVESYNC_OUTGOING_BUFFSIZE_SCRAPE - LIVESYNC_OUTGOING_WATERMARK_SCRAPE;

static size_t   g_inquire_remote_count;
static uint32_t g_inquire_remote_host;
static int      g_inquire_inprogress;
static int      g_inquire_bucket;
#endif /* WANT_SYNC_SCRAPE */

static pthread_t thread_id;
void livesync_init( ) {
  if( g_socket_in == -1 )
    exerr( "No socket address for live sync specified." );

  /* Prepare outgoing peers buffer */
  g_peerbuffer_pos = g_peerbuffer_start;
  memcpy( g_peerbuffer_pos, &g_tracker_id, sizeof( g_tracker_id ) );
  uint32_pack_big( (char*)g_peerbuffer_pos + sizeof( g_tracker_id ), OT_SYNC_PEER);
  g_peerbuffer_pos += sizeof( g_tracker_id ) + sizeof( uint32_t);

#ifdef WANT_SYNC_SCRAPE
  /* Prepare outgoing scrape buffer */
  g_scrapebuffer_pos = g_scrapebuffer_start;
  memcpy( g_scrapebuffer_pos, &g_tracker_id, sizeof( g_tracker_id ) );
  uint32_pack_big( (char*)g_scrapebuffer_pos + sizeof( g_tracker_id ), OT_SYNC_SCRAPE_TELL);
  g_scrapebuffer_pos += sizeof( g_tracker_id ) + sizeof( uint32_t);

  /* Wind up timers for inquires */
  g_next_beacon_time = g_now_seconds + LIVESYNC_FIRST_BEACON_DELAY;
#endif /* WANT_SYNC_SCRAPE */
  g_next_packet_time = g_now_seconds + LIVESYNC_MAXDELAY;

  pthread_create( &thread_id, NULL, livesync_worker, NULL );
}

void livesync_deinit() {
  if( g_socket_in != -1 )
    close( g_socket_in );
  if( g_socket_out != -1 )
    close( g_socket_out );

  pthread_cancel( thread_id );
}

void livesync_bind_mcast( ot_ip6 ip, uint16_t port) {
  char tmpip[4] = {0,0,0,0};
  char *v4ip;

  if( !ip6_isv4mapped(ip))
    exerr("v6 mcast support not yet available.");
  v4ip = ip+12;

  if( g_socket_in != -1 )
    exerr("Error: Livesync listen ip specified twice.");

  if( ( g_socket_in = socket_udp4( )) < 0)
    exerr("Error: Cant create live sync incoming socket." );
  ndelay_off(g_socket_in);

  if( socket_bind4_reuse( g_socket_in, tmpip, port ) == -1 )
    exerr("Error: Cant bind live sync incoming socket." );

  if( socket_mcjoin4( g_socket_in, groupip_1, v4ip ) )
    exerr("Error: Cant make live sync incoming socket join mcast group.");

  if( ( g_socket_out = socket_udp4()) < 0)
    exerr("Error: Cant create live sync outgoing socket." );
  if( socket_bind4_reuse( g_socket_out, v4ip, port ) == -1 )
    exerr("Error: Cant bind live sync outgoing socket." );

  socket_mcttl4(g_socket_out, 1);
  socket_mcloop4(g_socket_out, 0);
}

static void livesync_issue_peersync( ) {
  socket_send4(g_socket_out, (char*)g_peerbuffer_start, g_peerbuffer_pos - g_peerbuffer_start,
               groupip_1, LIVESYNC_PORT);
  g_peerbuffer_pos   = g_peerbuffer_start + sizeof( g_tracker_id ) + sizeof( uint32_t );
  g_next_packet_time = g_now_seconds + LIVESYNC_MAXDELAY;
}

static void livesync_handle_peersync( ssize_t datalen ) {
  int off = sizeof( g_tracker_id ) + sizeof( uint32_t );

  /* Now basic sanity checks have been done on the live sync packet
     We might add more testing and logging. */
  while( off + (ssize_t)sizeof( ot_hash ) + (ssize_t)sizeof( ot_peer ) <= datalen ) {
    ot_peer *peer = (ot_peer*)(g_inbuffer + off + sizeof(ot_hash));
    ot_hash *hash = (ot_hash*)(g_inbuffer + off);

    if( !g_opentracker_running ) return;

    if( OT_PEERFLAG(peer) & PEER_FLAG_STOPPED )
      remove_peer_from_torrent( *hash, peer, NULL, FLAG_MCA );
    else
      add_peer_to_torrent( *hash, peer, FLAG_MCA );

    off += sizeof( ot_hash ) + sizeof( ot_peer );
  }

  stats_issue_event(EVENT_SYNC, 0,
                    (datalen - sizeof( g_tracker_id ) - sizeof( uint32_t ) ) /
                    ((ssize_t)sizeof( ot_hash ) + (ssize_t)sizeof( ot_peer )));
}

#ifdef WANT_SYNC_SCRAPE
void livesync_issue_beacon( ) {
  size_t torrent_count = mutex_get_torrent_count();
  uint8_t beacon[ sizeof(g_tracker_id) + sizeof(uint32_t) + sizeof( uint64_t ) ];

  memcpy( beacon, &g_tracker_id, sizeof( g_tracker_id ) );
  uint32_pack_big( (char*)beacon + sizeof( g_tracker_id ), OT_SYNC_SCRAPE_BEACON);
  uint32_pack_big( (char*)beacon + sizeof( g_tracker_id ) +     sizeof(uint32_t), (uint32_t)((uint64_t)(torrent_count)>>32) );
  uint32_pack_big( (char*)beacon + sizeof( g_tracker_id ) + 2 * sizeof(uint32_t), (uint32_t)torrent_count );

  socket_send4(g_socket_out, (char*)beacon, sizeof(beacon), groupip_1, LIVESYNC_PORT);
}

void livesync_handle_beacon( ssize_t datalen ) {
  size_t torrent_count_local, torrent_count_remote;
  if( datalen != sizeof(g_tracker_id) + sizeof(uint32_t) + sizeof( uint64_t ) )
    return;
  torrent_count_local   = mutex_get_torrent_count();
  torrent_count_remote  = (size_t)(((uint64_t)uint32_read_big((char*)g_inbuffer+sizeof( g_tracker_id ) + sizeof(uint32_t))) << 32);
  torrent_count_remote |= (size_t)uint32_read_big((char*)g_inbuffer+sizeof( g_tracker_id ) + 2 * sizeof(uint32_t));

  /* Empty tracker is useless */
  if( !torrent_count_remote ) return;

  if( ((double)torrent_count_local ) / ((double)torrent_count_remote) < LIVESYNC_INQUIRE_THRESH) {
    if( !g_next_inquire_time ) {
      g_next_inquire_time    = g_now_seconds + 2 * LIVESYNC_BEACON_INTERVAL;
      g_inquire_remote_count = 0;
    }

    if( torrent_count_remote > g_inquire_remote_count ) {
      g_inquire_remote_count = torrent_count_remote;
      memcpy( &g_inquire_remote_host, g_inbuffer, sizeof( g_tracker_id ) );
    }
  }
}

void livesync_issue_inquire( ) {
  uint8_t inquire[ sizeof(g_tracker_id) + sizeof(uint32_t) + sizeof(g_tracker_id)];

  memcpy( inquire, &g_tracker_id, sizeof( g_tracker_id ) );
  uint32_pack_big( (char*)inquire + sizeof( g_tracker_id ), OT_SYNC_SCRAPE_INQUIRE);
  memcpy( inquire + sizeof(g_tracker_id) + sizeof(uint32_t), &g_inquire_remote_host, sizeof( g_tracker_id ) );

  socket_send4(g_socket_out, (char*)inquire, sizeof(inquire), groupip_1, LIVESYNC_PORT);
}

void livesync_handle_inquire( ssize_t datalen ) {
  if( datalen != sizeof(g_tracker_id) + sizeof(uint32_t) + sizeof(g_tracker_id) )
    return;

  /* If it isn't us, they're inquiring, ignore inquiry */
  if( memcmp( &g_tracker_id, g_inbuffer, sizeof( g_tracker_id ) ) )
    return;

  /* Start scrape tell on next ticker */
  if( !g_inquire_inprogress ) {
    g_inquire_inprogress = 1;
    g_inquire_bucket     = 0;
  }
}

void livesync_issue_tell( ) {
  int packets_to_send = LIVESYNC_OUTGOING_MAXPACKETS_SCRAPE;
  while( packets_to_send > 0 && g_inquire_bucket < OT_BUCKET_COUNT ) {
    ot_vector *torrents_list = mutex_bucket_lock( g_inquire_bucket );
    unsigned int j;
    for( j=0; j<torrents_list->size; ++j ) {
      ot_torrent *torrent = (ot_torrent*)(torrents_list->data) + j;
      memcpy(g_scrapebuffer_pos, torrent->hash, sizeof(ot_hash));
      g_scrapebuffer_pos += sizeof(ot_hash);
      uint32_pack_big( (char*)g_scrapebuffer_pos    , (uint32_t)(g_now_minutes - torrent->peer_list->base ));
      uint32_pack_big( (char*)g_scrapebuffer_pos + 4, (uint32_t)((uint64_t)(torrent->peer_list->down_count)>>32) );
      uint32_pack_big( (char*)g_scrapebuffer_pos + 8, (uint32_t)torrent->peer_list->down_count );
      g_scrapebuffer_pos += 12;

      if( g_scrapebuffer_pos >= g_scrapebuffer_highwater ) {
        socket_send4(g_socket_out, (char*)g_scrapebuffer_start, g_scrapebuffer_pos - g_scrapebuffer_start, groupip_1, LIVESYNC_PORT);
        g_scrapebuffer_pos = g_scrapebuffer_start + sizeof( g_tracker_id ) + sizeof( uint32_t);
        --packets_to_send;
      }
    }
    mutex_bucket_unlock( g_inquire_bucket++, 0 );
    if( !g_opentracker_running )
      return;
  }
  if( g_inquire_bucket == OT_BUCKET_COUNT ) {
    socket_send4(g_socket_out, (char*)g_scrapebuffer_start, g_scrapebuffer_pos - g_scrapebuffer_start, groupip_1, LIVESYNC_PORT);
    g_inquire_inprogress = 0;
  }
}

void livesync_handle_tell( ssize_t datalen ) {
  int off = sizeof( g_tracker_id ) + sizeof( uint32_t );

  /* Some instance is in progress of telling. Our inquiry was successful.
     Don't ask again until we see next beacon. */
  g_next_inquire_time = 0;

  /* Don't cause any new inquiries during another tracker's tell */
  if( g_next_beacon_time - g_now_seconds < LIVESYNC_BEACON_INTERVAL )
    g_next_beacon_time = g_now_seconds + LIVESYNC_BEACON_INTERVAL;

  while( off + sizeof(ot_hash) + 12 <= (size_t)datalen ) {
    ot_hash *hash = (ot_hash*)(g_inbuffer+off);
    ot_vector *torrents_list = mutex_bucket_lock_by_hash(*hash);
    size_t     down_count_remote;
    int exactmatch;
    ot_torrent * torrent = vector_find_or_insert(torrents_list, hash, sizeof(ot_hash), OT_HASH_COMPARE_SIZE, &exactmatch);
    if( !torrent ) {
      mutex_bucket_unlock_by_hash( *hash, 0 );
      continue;
    }

    if( !exactmatch ) {
      /* Create a new torrent entry, then */
      memcpy( &torrent->hash, hash, sizeof(ot_hash));

      if( !( torrent->peer_list = malloc( sizeof (ot_peerlist) ) ) ) {
        vector_remove_torrent( torrents_list, torrent );
        mutex_bucket_unlock_by_hash( *hash, 0 );
        continue;
      }

      byte_zero( torrent->peer_list, sizeof( ot_peerlist ) );
      torrent->peer_list->base = g_now_minutes - uint32_read_big((char*)g_inbuffer+off+sizeof(ot_hash));
    }

    down_count_remote  = (size_t)(((uint64_t)uint32_read_big((char*)g_inbuffer+off+sizeof(ot_hash ) +     sizeof(uint32_t))) << 32);
    down_count_remote |= (size_t)            uint32_read_big((char*)g_inbuffer+off+sizeof(ot_hash ) + 2 * sizeof(uint32_t));

    if( down_count_remote > torrent->peer_list->down_count )
      torrent->peer_list->down_count = down_count_remote;
    /* else
      We might think of sending a tell packet, if we have a much larger downloaded count
     */

    mutex_bucket_unlock( g_inquire_bucket++, exactmatch?0:1 );
    if( !g_opentracker_running )
      return;
    off += sizeof(ot_hash) + 12;
  }
}
#endif /* WANT_SYNC_SCRAPE */

/* Tickle the live sync module from time to time, so no events get
   stuck when there's not enough traffic to fill udp packets fast
   enough */
void livesync_ticker( ) {

  /* livesync_issue_peersync sets g_next_packet_time */
  if( g_now_seconds > g_next_packet_time &&
     g_peerbuffer_pos > g_peerbuffer_start + sizeof( g_tracker_id ) )
    livesync_issue_peersync();

#ifdef WANT_SYNC_SCRAPE
  /* Send first beacon after running at least LIVESYNC_FIRST_BEACON_DELAY
     seconds and not more often than every LIVESYNC_BEACON_INTERVAL seconds */
  if( g_now_seconds > g_next_beacon_time ) {
    livesync_issue_beacon( );
    g_next_beacon_time = g_now_seconds + LIVESYNC_BEACON_INTERVAL;
  }

  /* If we're interested in an inquiry and waited long enough to see all
     tracker's beacons, go ahead and inquire */
  if( g_next_inquire_time && g_now_seconds > g_next_inquire_time ) {
    livesync_issue_inquire();

    /* If packet gets lost, ask again after LIVESYNC_BEACON_INTERVAL */
    g_next_inquire_time = g_now_seconds + LIVESYNC_BEACON_INTERVAL;
  }

  /* If we're in process of telling, let's tell. */
  if( g_inquire_inprogress )
    livesync_issue_tell( );

#endif /* WANT_SYNC_SCRAPE */
}

/* Inform live sync about whats going on. */
void livesync_tell( ot_hash const info_hash, const ot_peer * const peer ) {

  memcpy( g_peerbuffer_pos, info_hash, sizeof(ot_hash) );
  memcpy( g_peerbuffer_pos+sizeof(ot_hash), peer, sizeof(ot_peer) );

  g_peerbuffer_pos += sizeof(ot_hash)+sizeof(ot_peer);

  if( g_peerbuffer_pos >= g_peerbuffer_highwater )
    livesync_issue_peersync();
}

static void * livesync_worker( void * args ) {
  ot_ip6 in_ip; uint16_t in_port;
  ssize_t datalen;

  (void)args;

  while( 1 ) {
    datalen = socket_recv4(g_socket_in, (char*)g_inbuffer, LIVESYNC_INCOMING_BUFFSIZE, (char*)in_ip, &in_port);

    /* Expect at least tracker id and packet type */
    if( datalen <= (ssize_t)(sizeof( g_tracker_id ) + sizeof( uint32_t )) )
      continue;
    if( !accesslist_isblessed(in_ip, OT_PERMISSION_MAY_LIVESYNC))
      continue;
    if( !memcmp( g_inbuffer, &g_tracker_id, sizeof( g_tracker_id ) ) ) {
      /* TODO: log packet coming from ourselves */
      continue;
    }

    switch( uint32_read_big( sizeof( g_tracker_id ) + (char*)g_inbuffer ) ) {
    case OT_SYNC_PEER:
      livesync_handle_peersync( datalen );
      break;
#ifdef WANT_SYNC_SCRAPE
    case OT_SYNC_SCRAPE_BEACON:
      livesync_handle_beacon( datalen );
      break;
    case OT_SYNC_SCRAPE_INQUIRE:
      livesync_handle_inquire( datalen );
      break;
    case OT_SYNC_SCRAPE_TELL:
      livesync_handle_tell( datalen );
      break;
#endif /* WANT_SYNC_SCRAPE */
    default:
      break;
    }
  }

  /* Never returns. */
  return NULL;
}

#endif
const char *g_version_livesync_c = "$Source$: $Revision$\n";
