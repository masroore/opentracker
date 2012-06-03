/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <stdlib.h>
#include <pthread.h>
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
#include "ot_rijndael.h"

static const uint8_t g_static_connid[8] = { 0x23, 0x42, 0x05, 0x17, 0xde, 0x41, 0x50, 0xff };
static uint32_t g_rijndael_round_key[44] = {0};
static uint32_t g_key_of_the_hour[2] = {0};
static ot_time  g_hour_of_the_key;

static void udp_generate_rijndael_round_key() {
  uint8_t key[16];
  key[0] = random(); key[1] = random(); key[2] = random(); key[3] = random();
  rijndaelKeySetupEnc128( g_rijndael_round_key, key );

  g_key_of_the_hour[0] = random();
  g_hour_of_the_key = g_now_minutes;
}

/* Generate current and previous connection id for ip */
static void udp_make_connectionid( uint32_t connid[2], const ot_ip6 remoteip, int age ) {
  uint32_t plain[4], crypt[4];
  int i;
  if( g_now_minutes + 60 > g_hour_of_the_key ) {
    g_hour_of_the_key = g_now_minutes;
    g_key_of_the_hour[1] = g_key_of_the_hour[0];
    g_key_of_the_hour[0] = random();
  }

  memcpy( plain, remoteip, sizeof( plain ) );
  for( i=0; i<4; ++i ) plain[i] ^= g_key_of_the_hour[age];
  rijndaelEncrypt128( g_rijndael_round_key, (uint8_t*)remoteip, (uint8_t*)crypt );
  connid[0] = crypt[0] ^ crypt[1];
  connid[1] = crypt[2] ^ crypt[3];
}

/* UDP implementation according to http://xbtt.sourceforge.net/udp_tracker_protocol.html */
int handle_udp6( int64 serversocket, struct ot_workstruct *ws ) {
  ot_ip6      remoteip;
  uint32_t   *inpacket = (uint32_t*)ws->inbuf;
  uint32_t   *outpacket = (uint32_t*)ws->outbuf;
  uint32_t    numwant, left, event, scopeid;
  uint32_t    connid[2];
  uint16_t    port, remoteport;
  size_t      byte_count, scrape_count;

  byte_count = socket_recv6( serversocket, ws->inbuf, G_INBUF_SIZE, remoteip, &remoteport, &scopeid );
  if( !byte_count ) return 0;

  stats_issue_event( EVENT_ACCEPT, FLAG_UDP, (uintptr_t)remoteip );
  stats_issue_event( EVENT_READ, FLAG_UDP, byte_count );

  /* Minimum udp tracker packet size, also catches error */
  if( byte_count < 16 )
    return 1;

  /* Generate the connection id we give out and expect to and from
     the requesting ip address, this prevents udp spoofing */
  udp_make_connectionid( connid, remoteip, 0 );

  /* Initialise hash pointer */
  ws->hash = NULL;
  ws->peer_id = NULL;

  /* If action is not a ntohl(a) == a == 0, then we
     expect the derived connection id in first 64 bit */
  if( inpacket[2] && ( inpacket[0] != connid[0] || inpacket[1] != connid[1] ) ) {
    /* If connection id does not match, try the one that was
       valid in the previous hour. Only if this also does not
       match, return an error packet */
    udp_make_connectionid( connid, remoteip, 1 );
    if( inpacket[0] != connid[0] || inpacket[1] != connid[1] ) {
      const size_t s = sizeof( "Connection ID missmatch." );
      outpacket[0] = 3; outpacket[1] = inpacket[3];
      memcpy( &outpacket[2], "Connection ID missmatch.", s );
      socket_send6( serversocket, ws->outbuf, 8 + s, remoteip, remoteport, 0 );
      stats_issue_event( EVENT_CONNID_MISSMATCH, FLAG_UDP, 8 + s );
      return 1;
    }
  }

  switch( ntohl( inpacket[2] ) ) {
    case 0: /* This is a connect action */
      /* look for udp bittorrent magic id */
      if( (ntohl(inpacket[0]) != 0x00000417) || (ntohl(inpacket[1]) != 0x27101980) )
        return 1;

      outpacket[0] = 0;
      outpacket[1] = inpacket[3];
      outpacket[2] = connid[0];
      outpacket[3] = connid[1];

      socket_send6( serversocket, ws->outbuf, 16, remoteip, remoteport, 0 );
      stats_issue_event( EVENT_CONNECT, FLAG_UDP, 16 );
      break;
    case 1: /* This is an announce action */
      /* Minimum udp announce packet size */
      if( byte_count < 98 )
        return 1;

      /* We do only want to know, if it is zero */
      left  = inpacket[64/4] | inpacket[68/4];

      numwant = ntohl( inpacket[92/4] );
      if (numwant > 200) numwant = 200;

      event    = ntohl( inpacket[80/4] );
      port     = *(uint16_t*)( ((char*)inpacket) + 96 );
      ws->hash = (ot_hash*)( ((char*)inpacket) + 16 );

      OT_SETIP( &ws->peer, remoteip );
      OT_SETPORT( &ws->peer, &port );
      OT_PEERFLAG( &ws->peer ) = 0;

      switch( event ) {
        case 1: OT_PEERFLAG( &ws->peer ) |= PEER_FLAG_COMPLETED; break;
        case 3: OT_PEERFLAG( &ws->peer ) |= PEER_FLAG_STOPPED; break;
        default: break;
      }

      if( !left )
        OT_PEERFLAG( &ws->peer )         |= PEER_FLAG_SEEDING;

      outpacket[0] = htonl( 1 );    /* announce action */
      outpacket[1] = inpacket[12/4];

      if( OT_PEERFLAG( &ws->peer ) & PEER_FLAG_STOPPED ) { /* Peer is gone. */
        ws->reply      = ws->outbuf;
        ws->reply_size = remove_peer_from_torrent( FLAG_UDP, ws );
      } else {
        ws->reply      = ws->outbuf + 8;
        ws->reply_size = 8 + add_peer_to_torrent_and_return_peers( FLAG_UDP, ws, numwant );
      }

      socket_send6( serversocket, ws->outbuf, ws->reply_size, remoteip, remoteport, 0 );
      stats_issue_event( EVENT_ANNOUNCE, FLAG_UDP, ws->reply_size );
      break;

    case 2: /* This is a scrape action */
      outpacket[0] = htonl( 2 );    /* scrape action */
      outpacket[1] = inpacket[12/4];

      for( scrape_count = 0; ( scrape_count * 20 < byte_count - 16) && ( scrape_count <= 74 ); scrape_count++ )
        return_udp_scrape_for_torrent( *(ot_hash*)( ((char*)inpacket) + 16 + 20 * scrape_count ), ((char*)outpacket) + 8 + 12 * scrape_count );

      socket_send6( serversocket, ws->outbuf, 8 + 12 * scrape_count, remoteip, remoteport, 0 );
      stats_issue_event( EVENT_SCRAPE, FLAG_UDP, scrape_count );
      break;
  }
  return 1;
}

static void* udp_worker( void * args ) {
  int64 sock = (int64)args;
  struct ot_workstruct ws;
  memset( &ws, 0, sizeof(ws) );

  ws.inbuf=malloc(G_INBUF_SIZE);
  ws.outbuf=malloc(G_OUTBUF_SIZE);
#ifdef    _DEBUG_HTTPERROR
  ws.debugbuf=malloc(G_DEBUGBUF_SIZE);
#endif

  while( g_opentracker_running )
    handle_udp6( sock, &ws );

  free( ws.inbuf );
  free( ws.outbuf );
#ifdef    _DEBUG_HTTPERROR
  free( ws.debugbuf );
#endif
  return NULL;
}

void udp_init( int64 sock, unsigned int worker_count ) {
  pthread_t thread_id;
  if( !g_rijndael_round_key[0] )
    udp_generate_rijndael_round_key();
#ifdef _DEBUG
  fprintf( stderr, " installing %d workers on udp socket %ld", worker_count, (unsigned long)sock );
#endif
  while( worker_count-- )
    pthread_create( &thread_id, NULL, udp_worker, (void *)sock );
}

const char *g_version_udp_c = "$Source$: $Revision$\n";
