/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

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

static const uint8_t g_static_connid[8] = { 0x23, 0x42, 0x05, 0x17, 0xde, 0x41, 0x50, 0xff };

static void udp_make_connectionid( uint32_t * connid, const ot_ip6 remoteip ) {
  /* Touch unused variable */
  (void)remoteip;

  /* Use a static secret for now */
  memcpy( connid, g_static_connid, 8 );
}

static int udp_test_connectionid( const uint32_t * const connid, const ot_ip6 remoteip ) {
  /* Touch unused variable */
  (void)remoteip;

  /* Test against our static secret */
  return !memcmp( connid, g_static_connid, 8 );
}

/* UDP implementation according to http://xbtt.sourceforge.net/udp_tracker_protocol.html */
void handle_udp6( int64 serversocket, struct ot_workstruct *ws ) {
  ot_peer     peer;
  ot_hash    *hash = NULL;
  ot_ip6      remoteip;
  uint32_t   *inpacket = (uint32_t*)ws->inbuf;
  uint32_t   *outpacket = (uint32_t*)ws->outbuf;
  uint32_t    numwant, left, event, scopeid;
  uint16_t    port, remoteport;
  size_t      r, r_out;

  r = socket_recv6( serversocket, ws->inbuf, G_INBUF_SIZE, remoteip, &remoteport, &scopeid );

  stats_issue_event( EVENT_ACCEPT, FLAG_UDP, (uintptr_t)remoteip );
  stats_issue_event( EVENT_READ, FLAG_UDP, r );

  /* Minimum udp tracker packet size, also catches error */
  if( r < 16 )
    return;

  switch( ntohl( inpacket[2] ) ) {
    case 0: /* This is a connect action */
      /* look for udp bittorrent magic id */
      if( (ntohl(inpacket[0]) != 0x00000417) || (ntohl(inpacket[1]) != 0x27101980) )
        return;

      outpacket[0] = 0;
      outpacket[1] = inpacket[3];
      udp_make_connectionid( outpacket + 2, remoteip );

      socket_send6( serversocket, ws->outbuf, 16, remoteip, remoteport, 0 );
      stats_issue_event( EVENT_CONNECT, FLAG_UDP, 16 );
      break;
    case 1: /* This is an announce action */
      /* Minimum udp announce packet size */
      if( r < 98 )
        return;

      if( !udp_test_connectionid( inpacket, remoteip ))
        fprintf( stderr, "UDP connect Connection id missmatch.\n" );

      /* We do only want to know, if it is zero */
      left  = inpacket[64/4] | inpacket[68/4];

      numwant = ntohl( inpacket[92/4] );
      if (numwant > 200) numwant = 200;

      event = ntohl( inpacket[80/4] );
      port  = *(uint16_t*)( ((char*)inpacket) + 96 );
      hash  = (ot_hash*)( ((char*)inpacket) + 16 );

      OT_SETIP( &peer, remoteip );
      OT_SETPORT( &peer, &port );
      OT_PEERFLAG( &peer ) = 0;

      switch( event ) {
        case 1: OT_PEERFLAG( &peer ) |= PEER_FLAG_COMPLETED; break;
        case 3: OT_PEERFLAG( &peer ) |= PEER_FLAG_STOPPED; break;
        default: break;
      }

      if( !left )
        OT_PEERFLAG( &peer )         |= PEER_FLAG_SEEDING;

      outpacket[0] = htonl( 1 );    /* announce action */
      outpacket[1] = inpacket[12/4];

      if( OT_PEERFLAG( &peer ) & PEER_FLAG_STOPPED ) /* Peer is gone. */
        r = remove_peer_from_torrent( *hash, &peer, ws->outbuf, FLAG_UDP );
      else
        r = 8 + add_peer_to_torrent_and_return_peers( *hash, &peer, FLAG_UDP, numwant, ((char*)outpacket) + 8 );

      socket_send6( serversocket, ws->outbuf, r, remoteip, remoteport, 0 );
      stats_issue_event( EVENT_ANNOUNCE, FLAG_UDP, r );
      break;

    case 2: /* This is a scrape action */
      if( !udp_test_connectionid( inpacket, remoteip ))
        fprintf( stderr, "UDP scrape Connection id missmatch.\n" );

      outpacket[0] = htonl( 2 );    /* scrape action */
      outpacket[1] = inpacket[12/4];

      for( r_out = 0; ( r_out * 20 < r - 16) && ( r_out <= 74 ); r_out++ )
        return_udp_scrape_for_torrent( *(ot_hash*)( ((char*)inpacket) + 16 + 20 * r_out ), ((char*)outpacket) + 8 + 12 * r_out );

      socket_send6( serversocket, ws->outbuf, 8 + 12 * r_out, remoteip, remoteport, 0 );
      stats_issue_event( EVENT_SCRAPE, FLAG_UDP, r );
      break;
  }
}

void udp_init( ) {

}

const char *g_version_udp_c = "$Source$: $Revision$\n";
