/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
 It is considered beerware. Prost. Skol. Cheers or whatever.
 
 $id$ */

/* System */
#include <sys/types.h>
#include <sys/uio.h>
#include <string.h>
#include <pthread.h>

/* Libowfat */
#include "socket.h"
#include "ndelay.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_livesync.h"
#include "ot_accesslist.h"

#ifdef WANT_SYNC_LIVE

char groupip_1[4] = { 224,0,23,42 };

#define LIVESYNC_BUFFINSIZE (256*256)
#define LIVESYNC_BUFFSIZE  1504
#define LIVESYNC_BUFFWATER (sizeof(ot_peer)+sizeof(ot_hash))

#define LIVESYNC_MAXDELAY  15

/* Forward declaration */
static void * livesync_worker( void * args );

/* For outgoing packets */
static int64 g_livesync_socket_in = -1;

/* For incoming packets */
static int64 g_livesync_socket_out = -1;

static uint8_t  livesync_inbuffer[LIVESYNC_BUFFINSIZE];
static uint8_t  livesync_outbuffer_start[ LIVESYNC_BUFFSIZE ];
static uint8_t *livesync_outbuffer_pos;
static uint8_t *livesync_outbuffer_highwater = livesync_outbuffer_start + LIVESYNC_BUFFSIZE - LIVESYNC_BUFFWATER;
static ot_time  livesync_lastpacket_time;

static pthread_t thread_id;
void livesync_init( ) {
  if( g_livesync_socket_in == -1 )
    exerr( "No socket address for live sync specified." );
  livesync_outbuffer_pos = livesync_outbuffer_start;
  memmove( livesync_outbuffer_pos, &g_tracker_id, sizeof( g_tracker_id ) );
  livesync_outbuffer_pos += sizeof( g_tracker_id );
  livesync_lastpacket_time = g_now;

  pthread_create( &thread_id, NULL, livesync_worker, NULL );
}
	
void livesync_deinit() {
  pthread_cancel( thread_id );
}

void livesync_bind_mcast( char *ip, uint16_t port) {
  char tmpip[4] = {0,0,0,0};

  if( g_livesync_socket_in != -1 )
    exerr("Error: Livesync listen ip specified twice.");

  if( ( g_livesync_socket_in = socket_udp4( )) < 0)
    exerr("Error: Cant create live sync incoming socket." );
  ndelay_off(g_livesync_socket_in);

  if( socket_bind4_reuse( g_livesync_socket_in, tmpip, port ) == -1 )
    exerr("Error: Cant bind live sync incoming socket." );

  if( socket_mcjoin4( g_livesync_socket_in, groupip_1, ip ) )
    exerr("Error: Cant make live sync incoming socket join mcast group.");

  if( ( g_livesync_socket_out = socket_udp4()) < 0)
    exerr("Error: Cant create live sync outgoing socket." );
  if( socket_bind4_reuse( g_livesync_socket_out, ip, port ) == -1 )
    exerr("Error: Cant bind live sync outgoing socket." );

  socket_mcttl4(g_livesync_socket_out, 1);
  socket_mcloop4(g_livesync_socket_out, 0);
}

static void livesync_issuepacket( ) {
  socket_send4(g_livesync_socket_out, (char*)livesync_outbuffer_start, livesync_outbuffer_pos - livesync_outbuffer_start,
               groupip_1, LIVESYNC_PORT);
  livesync_outbuffer_pos = livesync_outbuffer_start + sizeof( g_tracker_id );
  livesync_lastpacket_time = g_now;
}

/* Inform live sync about whats going on. */
void livesync_tell( ot_hash * const info_hash, const ot_peer * const peer, const uint8_t peerflag ) {
  memmove( livesync_outbuffer_pos                  , info_hash, sizeof(ot_hash));
  memmove( livesync_outbuffer_pos + sizeof(ot_hash), peer,      sizeof(ot_peer));
  OT_FLAG( livesync_outbuffer_pos + sizeof(ot_hash) ) |= peerflag;

  livesync_outbuffer_pos += sizeof(ot_hash) + sizeof(ot_peer);
  if( livesync_outbuffer_pos >= livesync_outbuffer_highwater )
    livesync_issuepacket();
}

/* Tickle the live sync module from time to time, so no events get
 stuck when there's not enough traffic to fill udp packets fast
 enough */
void livesync_ticker( ) {
	if( ( g_now - livesync_lastpacket_time > LIVESYNC_MAXDELAY) &&
      ( livesync_outbuffer_pos > livesync_outbuffer_start + sizeof( g_tracker_id ) ) )
    livesync_issuepacket();
}

static void * livesync_worker( void * args ) {
  uint8_t in_ip[4]; uint16_t in_port;
  ssize_t datalen;
  int off;
  
  args = args;

  while( 1 ) {
    datalen = socket_recv4(g_livesync_socket_in, (char*)livesync_inbuffer, LIVESYNC_BUFFINSIZE, (char*)in_ip, &in_port);
    off = 4;

    if( datalen <= 0 )
      continue;

    if( datalen < (ssize_t)(sizeof( g_tracker_id ) + sizeof( ot_hash ) + sizeof( ot_peer ) ) ) {
      // TODO: log invalid sync packet
      continue;
    }

    if( !accesslist_isblessed((char*)in_ip, OT_PERMISSION_MAY_LIVESYNC)) {
      // TODO: log invalid sync packet
      continue;
    }

    if( !memcmp( livesync_inbuffer, &g_tracker_id, sizeof( g_tracker_id ) ) ) {
      // TODO: log packet coming from ourselves
      continue;
    }

    // Now basic sanity checks have been done on the live sync packet
    // We might add more testing and logging.
    while( off + (ssize_t)sizeof( ot_hash ) + (ssize_t)sizeof( ot_peer ) <= datalen ) {
      ot_peer *peer = (ot_peer*)(livesync_inbuffer + off + sizeof(ot_hash));
      ot_hash *hash = (ot_hash*)(livesync_inbuffer + off);

      if( OT_FLAG(peer) & PEER_FLAG_STOPPED )
        remove_peer_from_torrent(hash, peer, NULL, FLAG_MCA);
      else
        add_peer_to_torrent( hash, peer  WANT_SYNC_PARAM(1));

      off += sizeof( ot_hash ) + sizeof( ot_peer );
    }
  }
  /* Never returns. */
  return NULL;
}

#endif
const char *g_version_livesync_c = "$Source$: $Revision$\n";
