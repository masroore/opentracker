/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $Id$ */

/* System */
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <pwd.h>
#include <ctype.h>

/* Libowfat */
#include "socket.h"
#include "io.h"
#include "iob.h"
#include "byte.h"
#include "scan.h"
#include "ip6.h"
#include "ndelay.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_livesync.h"

uint32_t g_tracker_id;
char groupip_1[4] = { 224,0,23,5 };

#define LIVESYNC_INCOMING_BUFFSIZE          (256*256)

#define LIVESYNC_OUTGOING_BUFFSIZE_PEERS     1480
#define LIVESYNC_OUTGOING_WATERMARK_PEERS   (sizeof(ot_peer)+sizeof(ot_hash))

enum { OT_SYNC_PEER };

/* For outgoing packets */
static int64    g_socket_in = -1;

/* For incoming packets */
static int64    g_socket_out = -1;
static uint8_t  g_inbuffer[LIVESYNC_INCOMING_BUFFSIZE];

void exerr( char * message ) {
  fprintf( stderr, "%s\n", message );
  exit( 111 );
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
  socket_mcloop4(g_socket_out, 1);
}

static ot_vector all_torrents[OT_BUCKET_COUNT];
ot_vector *mutex_bucket_lock_by_hash( ot_hash hash ) {
  return all_torrents + ( uint32_read_big( (char*)hash ) >> OT_BUCKET_COUNT_SHIFT );
}
ot_vector *mutex_bucket_lock( int bucket ) {
  return all_torrents + bucket;
}
#define mutex_bucket_unlock_by_hash(A,B)
#define mutex_bucket_unlock(A)

size_t add_peer_to_torrent_proxy( ot_hash hash, ot_peer *peer ) {
  int         exactmatch;
  ot_torrent *torrent;
  ot_peer    *peer_dest;
  ot_vector  *torrents_list = mutex_bucket_lock_by_hash( hash );

  torrent = vector_find_or_insert( torrents_list, (void*)hash, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );
  if( !torrent )
    return -1;

  if( !exactmatch ) {
    /* Create a new torrent entry, then */
    memcpy( torrent->hash, hash, sizeof(ot_hash) );

    if( !( torrent->peer_list = malloc( sizeof (ot_peerlist) ) ) ) {
      vector_remove_torrent( torrents_list, torrent );
      return -1;
    }

    byte_zero( torrent->peer_list, sizeof( ot_peerlist ) );
  }

  /* Check for peer in torrent */
  peer_dest = vector_find_or_insert_peer( &(torrent->peer_list->peers), peer, &exactmatch );
  if( !peer_dest ) return -1;

  /* Tell peer that it's fresh */
  OT_PEERTIME( peer ) = 0;

  /* If we hadn't had a match create peer there */
  if( !exactmatch ) {
    torrent->peer_list->peer_count++;
    if( OT_PEERFLAG(peer) & PEER_FLAG_SEEDING )
      torrent->peer_list->seed_count++;
  }
  memcpy( peer_dest, peer, sizeof(ot_peer) );
  return 0;
}

size_t remove_peer_from_torrent_proxy( ot_hash hash, ot_peer *peer ) {
  int          exactmatch;
  ot_vector   *torrents_list = mutex_bucket_lock_by_hash( hash );
  ot_torrent  *torrent = binary_search( hash, torrents_list->data, torrents_list->size, sizeof( ot_torrent ), OT_HASH_COMPARE_SIZE, &exactmatch );

  if( exactmatch ) {
    ot_peerlist *peer_list = torrent->peer_list;
    switch( vector_remove_peer( &peer_list->peers, peer ) ) {
      case 2:  peer_list->seed_count--; /* Fall throughs intended */
      case 1:  peer_list->peer_count--; /* Fall throughs intended */
      default: break;
    }
  }

  return 0;
}

void free_peerlist( ot_peerlist *peer_list ) {
  if( peer_list->peers.data ) {
    if( OT_PEERLIST_HASBUCKETS( peer_list ) ) {
      ot_vector *bucket_list = (ot_vector*)(peer_list->peers.data);

      while( peer_list->peers.size-- )
        free( bucket_list++->data );
    }
    free( peer_list->peers.data );
  }
  free( peer_list );
}

static void livesync_handle_peersync( ssize_t datalen ) {
  int off = sizeof( g_tracker_id ) + sizeof( uint32_t );

  /* Now basic sanity checks have been done on the live sync packet
     We might add more testing and logging. */
  while( off + (ssize_t)sizeof( ot_hash ) + (ssize_t)sizeof( ot_peer ) <= datalen ) {
    ot_peer *peer = (ot_peer*)(g_inbuffer + off + sizeof(ot_hash));
    ot_hash *hash = (ot_hash*)(g_inbuffer + off);

    if( OT_PEERFLAG(peer) & PEER_FLAG_STOPPED )
      remove_peer_from_torrent_proxy( *hash, peer );
    else
      add_peer_to_torrent_proxy( *hash, peer );

    off += sizeof( ot_hash ) + sizeof( ot_peer );
  }
}

int usage( char *self ) {
  fprintf( stderr, "Usage: %s -i ip -p port\n", self );
  return 0;
}

static uint32_t peer_counts[1024];
#ifdef WANT_SCROOOOOOOLL
static char*to_hex(char*d,uint8_t*s){char*m="0123456789ABCDEF";char *t=d;char*e=d+40;while(d<e){*d++=m[*s>>4];*d++=m[*s++&15];}*d=0;return t;}
#endif

int main( int argc, char **argv ) {
  ot_ip6 serverip;
  uint16_t tmpport;
  int scanon = 1, bound = 0;
  time_t next_dump = time(NULL)+1;

  srandom( time(NULL) );
  g_tracker_id = random();

  while( scanon ) {
    switch( getopt( argc, argv, ":i:p:vh" ) ) {
    case -1: scanon = 0; break;
    case 'i': 
      if( !scan_ip6( optarg, serverip )) { usage( argv[0] ); exit( 1 ); }
      break;
    case 'p':
      if( !scan_ushort( optarg, &tmpport)) { usage( argv[0] ); exit( 1 ); }
      livesync_bind_mcast( serverip, tmpport); bound++; break;
    default:
    case '?': usage( argv[0] ); exit( 1 );
    }
  }

  if( !bound ) exerr( "No port bound." );

  while( 1 ) {
    ot_ip6 in_ip; uint16_t in_port;
    size_t datalen = socket_recv4(g_socket_in, (char*)g_inbuffer, LIVESYNC_INCOMING_BUFFSIZE, 12+(char*)in_ip, &in_port);

    /* Expect at least tracker id and packet type */
    if( datalen <= (ssize_t)(sizeof( g_tracker_id ) + sizeof( uint32_t )) )
      continue;
    if( !memcmp( g_inbuffer, &g_tracker_id, sizeof( g_tracker_id ) ) ) {
      /* drop packet coming from ourselves */
      continue;
    }

    switch( uint32_read_big( sizeof( g_tracker_id ) + (char*)g_inbuffer ) ) {
    case OT_SYNC_PEER:
      livesync_handle_peersync( datalen );
      break;
    default:
      fprintf( stderr, "Received an unknown live sync packet type %u.\n", uint32_read_big( sizeof( g_tracker_id ) + (char*)g_inbuffer ) );
      break;
    }
    if( time(NULL) > next_dump ) {
      int bucket, i;
      /* For each bucket... */
      for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
        /* Get exclusive access to that bucket */
        ot_vector *torrents_list = mutex_bucket_lock( bucket );
        size_t tor_offset;

        /* For each torrent in this bucket.. */
        for( tor_offset=0; tor_offset<torrents_list->size; ++tor_offset ) {
          /* Address torrents members */
          ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[tor_offset] ).peer_list;
#ifdef WANT_SCROOOOOOOLL
          ot_hash     *hash      =&( ((ot_torrent*)(torrents_list->data))[tor_offset] ).hash;
          char hash_out[41];
          to_hex(hash_out,*hash);
          printf( "%s %08zd\n", hash_out, peer_list->peer_count );
#endif
          if(peer_list->peer_count<1024) peer_counts[peer_list->peer_count]++; else peer_counts[1023]++;
          free_peerlist(peer_list);
        }
        free( torrents_list->data );
        memset( torrents_list, 0, sizeof(*torrents_list ) );
      }
      for( i=1023; i>=0; --i )
        if( peer_counts[i] ) {
          printf( "%d:%d ", i, peer_counts[i] );
          peer_counts[i] = 0;
        }
      printf( "\n" );
      next_dump = time(NULL) + 1;
    } 
  }
}
