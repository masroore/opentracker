/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

/* System */
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

/* Libowfat */
#include "socket.h"
#include "io.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_udp.h"
#include "ot_stats.h"

static char static_inbuf[8192];
static char static_outbuf[8192];

static const uint8_t g_static_connid[8] = { 0x23, 0x42, 0x05, 0x17, 0xde, 0x41, 0x50, 0xff };

static void udp_make_connectionid( uint32_t * connid, const char * remoteip ) {
  /* Touch unused variable */
  remoteip = remoteip;

  /* Use a static secret for now */
  memcpy( connid, g_static_connid, 8 );
}

static int udp_test_connectionid( const uint32_t * const connid, const char * remoteip ) {
  /* Touch unused variable */
  remoteip = remoteip;

  /* Test against our static secret */
  return !memcmp( connid, g_static_connid, 8 );
}

/* UDP implementation according to http://xbtt.sourceforge.net/udp_tracker_protocol.html */
void handle_udp4( int64 serversocket ) {
  ot_peer     peer;
  ot_torrent *torrent;
  ot_hash    *hash = NULL;
  char        remoteip[4];
  uint32_t   *inpacket = (uint32_t*)static_inbuf;
  uint32_t   *outpacket = (uint32_t*)static_outbuf;
  uint32_t    numwant, left, event;
  uint16_t    port, remoteport;
  size_t      r, r_out;

  r = socket_recv4( serversocket, static_inbuf, sizeof( static_inbuf ), remoteip, &remoteport);

  stats_issue_event( EVENT_ACCEPT, 0, 0 );
  stats_issue_event( EVENT_READ, 0, r );

  /* Minimum udp tracker packet size, also catches error */
  if( r < 16 )
    return;

  /* look for udp bittorrent magic id */
  if( (ntohl(inpacket[0]) != 0x00000417) || (ntohl(inpacket[1]) != 0x27101980) )
    return;

  switch( ntohl( inpacket[2] ) ) {
    case 0: /* This is a connect action */
      outpacket[0] = 0;
      outpacket[1] = inpacket[3];
      udp_make_connectionid( outpacket + 2, remoteip );
      socket_send4( serversocket, static_outbuf, 16, remoteip, remoteport );
      stats_issue_event( EVENT_CONNECT, 0, 16 );
      break;
    case 1: /* This is an announce action */
      /* Minimum udp announce packet size */
      if( r < 98 )
        return;

      if( !udp_test_connectionid( inpacket, remoteip ))
        fprintf( stderr, "UDP Connection id missmatch, %16llX\n", *(uint64_t*)inpacket );

      numwant = 200;
      /* We do only want to know, if it is zero */
      left  = inpacket[64/4] | inpacket[68/4];

      event = ntohl( inpacket[80/4] );
      port  = *(uint16_t*)( static_inbuf + 96 );
      hash  = (ot_hash*)( static_inbuf + 16 );

      OT_SETIP( &peer, remoteip );
      OT_SETPORT( &peer, &port );
      OT_FLAG( &peer ) = 0;

      switch( event ) {
        case 1: OT_FLAG( &peer ) |= PEER_FLAG_COMPLETED; break;
        case 3: OT_FLAG( &peer ) |= PEER_FLAG_STOPPED; break;
        default: break;
      }

      if( !left )
        OT_FLAG( &peer )         |= PEER_FLAG_SEEDING;

      outpacket[0] = htonl( 1 );    /* announce action */
      outpacket[1] = inpacket[12/4];

      if( OT_FLAG( &peer ) & PEER_FLAG_STOPPED ) /* Peer is gone. */
        r = remove_peer_from_torrent( hash, &peer, static_outbuf, 0 );
      else {
        torrent = add_peer_to_torrent( hash, &peer  WANT_TRACKER_SYNC_PARAM( 0 ) );
        if( !torrent )
          return; /* XXX maybe send error */

        r = 8 + return_peers_for_torrent( hash, numwant, static_outbuf + 8, 0 );
      }

      socket_send4( serversocket, static_outbuf, r, remoteip, remoteport );
      stats_issue_event( EVENT_ANNOUNCE, 0, r );
      break;

    case 2: /* This is a scrape action */
      if( !udp_test_connectionid( inpacket, remoteip ))
        fprintf( stderr, "UDP Connection id missmatch, %16llX\n", *(uint64_t*)inpacket );

      outpacket[0] = htonl( 2 );    /* scrape action */
      outpacket[1] = inpacket[12/4];

      for( r_out = 0; ( r_out * 20 < r - 16) && ( r_out <= 74 ); r_out++ )
        return_udp_scrape_for_torrent( (ot_hash*)( static_inbuf + 16 + 20 * r_out ), static_outbuf + 8 + 12 * r_out );

      socket_send4( serversocket, static_outbuf, 8 + 12 * r_out, remoteip, remoteport );
      stats_issue_event( EVENT_SCRAPE, 0, r );
      break;
  }
}
