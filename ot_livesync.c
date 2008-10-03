/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
 It is considered beerware. Prost. Skol. Cheers or whatever.
 
 $id$ */

/* System */
#include <sys/types.h>
#include <sys/uio.h>
#include <string.h>

/* Libowfat */
#include "socket.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_livesync.h"
#include "ot_accesslist.h"

#ifdef WANT_SYNC_LIVE
char groupip_1[4] = { LIVESYNC_MCASTDOMAIN_1 };

/* For outgoing packets */
int64 g_livesync_socket = -1;

static uint8_t  livesync_inbuffer[LIVESYNC_BUFFINSIZE];
static uint8_t  livesync_outbuffer_start[ LIVESYNC_BUFFSIZE ];
static uint8_t *livesync_outbuffer_pos;
static uint8_t *livesync_outbuffer_highwater = livesync_outbuffer_start + LIVESYNC_BUFFSIZE - LIVESYNC_BUFFWATER;
static ot_time  livesync_lastpacket_time;

void livesync_init( ) {
  if( g_livesync_socket == -1 )
    exerr( "No socket address for live sync specified." );
  livesync_outbuffer_pos = livesync_outbuffer_start;
  memmove( livesync_outbuffer_pos, &g_tracker_id, sizeof( g_tracker_id ) );
  livesync_outbuffer_pos += sizeof( g_tracker_id );
  livesync_lastpacket_time = g_now;
}
	
void livesync_deinit() {
	
}

void livesync_bind_mcast( char *ip, uint16_t port) {
  char tmpip[4] = {0,0,0,0};
  if( g_livesync_socket != -1 )
    exerr("Livesync listen ip specified twice.");
  if( socket_mcjoin4( ot_try_bind(tmpip, port, FLAG_MCA ), groupip_1, ip ) )
    exerr("Cant join mcast group.");
  g_livesync_socket = ot_try_bind( ip, port, FLAG_UDP );
  io_dontwantread(g_livesync_socket);

  socket_mcttl4(g_livesync_socket, 1);
  socket_mcloop4(g_livesync_socket, 0);
}

static void livesync_issuepacket( ) {
	socket_send4(g_livesync_socket, (char*)livesync_outbuffer_start, livesync_outbuffer_pos - livesync_outbuffer_start,
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

/* Handle an incoming live sync packet */
void handle_livesync( int64 serversocket ) {
  uint8_t in_ip[4]; uint16_t in_port;
  ssize_t datalen = socket_recv4(serversocket, (char*)livesync_inbuffer, LIVESYNC_BUFFINSIZE, (char*)in_ip, &in_port);
  int off = 4;

  if( datalen < (ssize_t)(sizeof( g_tracker_id ) + sizeof( ot_hash ) + sizeof( ot_peer ) ) ) {
    // TODO: log invalid sync packet
    return;
  }

  if( !accesslist_isblessed((char*)in_ip, OT_PERMISSION_MAY_LIVESYNC)) {
    // TODO: log invalid sync packet
    return;
  }

  if( !memcmp( livesync_inbuffer, &g_tracker_id, sizeof( g_tracker_id ) ) ) {
    // TODO: log packet coming from ourselves
    return;
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

#endif
const char *g_version_livesync_c = "$Source$: $Revision$\n";
