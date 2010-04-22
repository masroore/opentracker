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

#define LIVESYNC_MAXDELAY                    15      /* seconds */

enum { OT_SYNC_PEER };

/* Forward declaration */
static void * livesync_worker( void * args );

/* For outgoing packets */
static int64    g_socket_in = -1;

/* For incoming packets */
static int64    g_socket_out = -1;

char            g_outbuf[LIVESYNC_OUTGOING_BUFFSIZE_PEERS];
static size_t   g_outbuf_data;
static ot_time  g_next_packet_time;

static pthread_t thread_id;
void livesync_init( ) {
  
  if( g_socket_in == -1 )
    exerr( "No socket address for live sync specified." );

  /* Prepare outgoing peers buffer */
  memcpy( g_outbuf, &g_tracker_id, sizeof( g_tracker_id ) );
  uint32_pack_big( g_outbuf + sizeof( g_tracker_id ), OT_SYNC_PEER);
  g_outbuf_data = sizeof( g_tracker_id ) + sizeof( uint32_t );

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
  socket_send4(g_socket_out, g_outbuf, g_outbuf_data, groupip_1, LIVESYNC_PORT);
  g_outbuf_data = sizeof( g_tracker_id ) + sizeof( uint32_t );
  g_next_packet_time = g_now_seconds + LIVESYNC_MAXDELAY;
}

static void livesync_handle_peersync( struct ot_workstruct *ws ) {
  int off = sizeof( g_tracker_id ) + sizeof( uint32_t );

  /* Now basic sanity checks have been done on the live sync packet
     We might add more testing and logging. */
  while( off + (ssize_t)sizeof( ot_hash ) + (ssize_t)sizeof( ot_peer ) <= ws->request_size ) {
    memcpy( &ws->peer, ws->request + off + sizeof(ot_hash), sizeof( ot_peer ) );
    ws->hash = (ot_hash*)(ws->request + off);

    if( !g_opentracker_running ) return;

    if( OT_PEERFLAG(&ws->peer) & PEER_FLAG_STOPPED )
      remove_peer_from_torrent( FLAG_MCA, ws );
    else
      add_peer_to_torrent_and_return_peers( FLAG_MCA, ws, /* amount = */ 0 );

    off += sizeof( ot_hash ) + sizeof( ot_peer );
  }

  stats_issue_event(EVENT_SYNC, 0,
                    (ws->request_size - sizeof( g_tracker_id ) - sizeof( uint32_t ) ) /
                    ((ssize_t)sizeof( ot_hash ) + (ssize_t)sizeof( ot_peer )));
}

/* Tickle the live sync module from time to time, so no events get
   stuck when there's not enough traffic to fill udp packets fast
   enough */
void livesync_ticker( ) {
  /* livesync_issue_peersync sets g_next_packet_time */
  if( g_now_seconds > g_next_packet_time &&
     g_outbuf_data > sizeof( g_tracker_id ) + sizeof( uint32_t ) )
    livesync_issue_peersync();
}

/* Inform live sync about whats going on. */
void livesync_tell( struct ot_workstruct *ws ) {

  memcpy( g_outbuf + g_outbuf_data, ws->hash, sizeof(ot_hash) );
  memcpy( g_outbuf + g_outbuf_data + sizeof(ot_hash), &ws->peer, sizeof(ot_peer) );

  g_outbuf_data += sizeof(ot_hash) + sizeof(ot_peer);

  if( g_outbuf_data >= LIVESYNC_OUTGOING_BUFFSIZE_PEERS - LIVESYNC_OUTGOING_WATERMARK_PEERS )
    livesync_issue_peersync();
}

static void * livesync_worker( void * args ) {
  struct ot_workstruct ws;
  ot_ip6 in_ip; uint16_t in_port;

  (void)args;
  
  /* Initialize our "thread local storage" */
  ws.inbuf   = ws.request = malloc( LIVESYNC_INCOMING_BUFFSIZE );
  ws.outbuf  = ws.reply   = 0;
  
  memcpy( in_ip, V4mappedprefix, sizeof( V4mappedprefix ) );

  while( 1 ) {
    ws.request_size = socket_recv4(g_socket_in, (char*)ws.inbuf, LIVESYNC_INCOMING_BUFFSIZE, 12+(char*)in_ip, &in_port);

    /* Expect at least tracker id and packet type */
    if( ws.request_size <= (ssize_t)(sizeof( g_tracker_id ) + sizeof( uint32_t )) )
      continue;
    if( !accesslist_isblessed(in_ip, OT_PERMISSION_MAY_LIVESYNC))
      continue;
    if( !memcmp( ws.inbuf, &g_tracker_id, sizeof( g_tracker_id ) ) ) {
      /* TODO: log packet coming from ourselves */
      continue;
    }

    switch( uint32_read_big( sizeof( g_tracker_id ) + (char *)ws.inbuf ) ) {
    case OT_SYNC_PEER:
      livesync_handle_peersync( &ws );
      break;
    default:
      break;
    }
  }

  /* Never returns. */
  return NULL;
}

#endif
const char *g_version_livesync_c = "$Source$: $Revision$\n";
