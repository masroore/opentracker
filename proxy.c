/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $Id$ */

/* System */
#include <stdint.h>
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
#include <pthread.h>

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
#include "ot_vector.h"
#include "ot_mutex.h"
#include "ot_livesync.h"
#include "ot_stats.h"

ot_ip6   g_serverip; 
uint16_t g_serverport = 9009;
uint32_t g_tracker_id;
char     groupip_1[4] = { 224,0,23,5 };
int      g_self_pipe[2];

/* If you have more than 10 peers, don't use this proxy
   Use 20 slots for 10 peers to have room for 10 incoming connection slots
 */
#define MAX_PEERS 20

#define LIVESYNC_INCOMING_BUFFSIZE          (256*256)
#define STREAMSYNC_OUTGOING_BUFFSIZE        (256*256)

#define LIVESYNC_OUTGOING_BUFFSIZE_PEERS     1480
#define LIVESYNC_OUTGOING_WATERMARK_PEERS   (sizeof(ot_peer)+sizeof(ot_hash))

/* The amount of time a complete sync cycle should take */
#define OT_SYNC_INTERVAL_MINUTES             2

/* So after each bucket wait 1 / OT_BUCKET_COUNT intervals */
#define OT_SYNC_SLEEP ( ( ( OT_SYNC_INTERVAL_MINUTES ) * 60 * 1000000 ) / ( OT_BUCKET_COUNT ) )

enum { OT_SYNC_PEER };
enum { FLAG_SERVERSOCKET = 1 };

/* For incoming packets */
static int64    g_socket_in = -1;
static uint8_t  g_inbuffer[LIVESYNC_INCOMING_BUFFSIZE];

/* For outgoing packets */
static int64    g_socket_out = -1;
//static uint8_t  g_outbuffer[STREAMSYNC_OUTGOING_BUFFSIZE];

static void * livesync_worker( void * args );
static void * streamsync_worker( void * args );

void exerr( char * message ) {
  fprintf( stderr, "%s\n", message );
  exit( 111 );
}

void stats_issue_event( ot_status_event event, PROTO_FLAG proto, uintptr_t event_data ) {
  (void) event;
  (void) proto;
  (void) event_data;
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
      mutex_bucket_unlock_by_hash( hash, 0 );
      return -1;
    }

    byte_zero( torrent->peer_list, sizeof( ot_peerlist ) );
  }

  /* Check for peer in torrent */
  peer_dest = vector_find_or_insert_peer( &(torrent->peer_list->peers), peer, &exactmatch );
  if( !peer_dest ) {
    mutex_bucket_unlock_by_hash( hash, 0 );
    return -1;
  }
  /* Tell peer that it's fresh */
  OT_PEERTIME( peer ) = 0;

  /* If we hadn't had a match create peer there */
  if( !exactmatch ) {
    torrent->peer_list->peer_count++;
    if( OT_PEERFLAG(peer) & PEER_FLAG_SEEDING )
      torrent->peer_list->seed_count++;
  }
  memcpy( peer_dest, peer, sizeof(ot_peer) );
  mutex_bucket_unlock_by_hash( hash, 0 );
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

  mutex_bucket_unlock_by_hash( hash, 0 );
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

enum {
  FLAG_OUTGOING      = 0x80,

  FLAG_DISCONNECTED  = 0x00,
  FLAG_CONNECTING    = 0x01,
  FLAG_WAITTRACKERID = 0x02,
  FLAG_CONNECTED     = 0x03,

  FLAG_MASK          = 0x07
};

#define PROXYPEER_NEEDSCONNECT(flag)      ((flag)==FLAG_OUTGOING)
#define PROXYPEER_SETDISCONNECTED(flag)   (flag)=(((flag)&FLAG_OUTGOING)|FLAG_DISCONNECTED)
#define PROXYPEER_SETCONNECTING(flag)     (flag)=(((flag)&FLAG_OUTGOING)|FLAG_CONNECTING)
#define PROXYPEER_SETWAITTRACKERID(flag)  (flag)=(((flag)&FLAG_OUTGOING)|FLAG_WAITTRACKERID)
#define PROXYPEER_SETCONNECTED(flag)      (flag)=(((flag)&FLAG_OUTGOING)|FLAG_CONNECTED)

typedef struct {
  int      state;          /* Whether we want to connect, how far our handshake is, etc. */
  ot_ip6   ip;             /* The peer to connect to */
  uint16_t port;           /* The peers port */
  uint8_t *indata;         /* Any data not processed yet */
  size_t   indata_length;  /* Length of unprocessed data */
  uint32_t tracker_id;     /* How the other end greeted */
  int64    fd;             /* A file handle, if connected, <= 0 is disconnected (0 initially, -1 else) */
  io_batch outdata;        /* The iobatch containing our sync data */
} proxy_peer;

/* Number of connections to peers
   * If a peer's IP is set, we try to reconnect, when the connection drops
   * If we already have a connected tracker_id in our records for an _incoming_ connection, drop it
   * Multiple connections to/from the same ip are okay, if tracker_id doesn't match
   * Reconnect attempts occur only twice a minute
*/
static int        g_connection_count;
static ot_time    g_connection_reconn;
static proxy_peer g_connections[MAX_PEERS];

static void handle_reconnects( void ) {
  int i;
  for( i=0; i<g_connection_count; ++i )
    if( PROXYPEER_NEEDSCONNECT( g_connections[i].state ) ) {
      int64 newfd = socket_tcp6( );
      if( newfd < 0 ) continue; /* No socket for you */
      io_fd(newfd);
      if( socket_bind6_reuse(newfd,g_serverip,g_serverport,0) ) {
        io_close( newfd );
        continue;
      }
      if( socket_connect6(newfd,g_connections[i].ip,g_connections[i].port,0) == -1 &&
          errno != EINPROGRESS && errno != EWOULDBLOCK ) {
        close(newfd);
        continue;
      }
      io_wantwrite(newfd); /* So we will be informed when it is connected */
      io_setcookie(newfd,g_connections+i);

      /* Prepare connection info block */
      free( g_connections[i].indata );
      g_connections[i].indata        = 0;
      g_connections[i].indata_length = 0;
      g_connections[i].fd            = newfd;
      g_connections[i].tracker_id    = 0;
      iob_reset( &g_connections[i].outdata );
      PROXYPEER_SETCONNECTING( g_connections[i].state );
    }
  g_connection_reconn = time(NULL) + 30;
}

/* Handle incoming connection requests, check against whitelist */
static void handle_accept( int64 serversocket ) {
  int64 newfd;
  ot_ip6 ip;
  uint16 port;

  while( ( newfd = socket_accept6( serversocket, ip, &port, NULL ) ) != -1 ) {

    /* XXX some access control */

    /* Put fd into a non-blocking mode */
    io_nonblock( newfd );

    if( !io_fd( newfd ) )
      io_close( newfd );
    else {
      /* Find a new home for our incoming connection */
      int i;
      for( i=0; i<MAX_PEERS; ++i )
        if( g_connections[i].state == FLAG_DISCONNECTED )
          break;
      if( i == MAX_PEERS ) {
        fprintf( stderr, "No room for incoming connection." );
        close( newfd );
        continue;
      }

      /* Prepare connection info block */
      free( g_connections[i].indata );
      g_connections[i].indata        = 0;
      g_connections[i].indata_length = 0;
      g_connections[i].port          = port;
      g_connections[i].fd            = newfd;
      g_connections[i].tracker_id    = 0;
      iob_reset( &g_connections[i].outdata );
      g_connections[i].tracker_id    = 0;

      PROXYPEER_SETCONNECTING( g_connections[i].state );

      io_setcookie( newfd, g_connections + i );

      /* We expect the connecting side to begin with its tracker_id */
      io_wantread( newfd );
    }
  }

  return;
}

/* New sync data on the stream */
static void handle_read( int64 peersocket ) {
  uint32_t tracker_id;
  proxy_peer *peer = io_getcookie( peersocket );
  if( !peer ) {
    /* Can't happen ;) */
    close( peersocket );
    return;
  }
  switch( peer->state & FLAG_MASK ) {
  case FLAG_DISCONNECTED: break; /* Shouldnt happen */
  case FLAG_CONNECTING:
  case FLAG_WAITTRACKERID:
    /* We want at least the first four bytes to come at once, to avoid keeping extra states (for now) */
    if( io_tryread( peersocket, &tracker_id, sizeof( tracker_id ) ) != sizeof( tracker_id ) )
      goto close_socket;

    /* See, if we already have a connection to that peer */
    for( i=0; i<MAX_PEERS; ++i )
      if( ( g_connections[i].state & FLAG_MASK ) == FLAG_CONNECTED && 
            g_connections[i].tracker_id == tracker_id )
        goto close_socket;

    /* Also no need for soliloquy */
    if( tracker_id == g_tracker_id )
      goto close_socket;

    /* The new connection is good, send our tracker_id on incoming connections */
    if( peer->state == FLAG_CONNECTING )
      io_trywrite( peersocket, (void*)&g_tracker_id, sizeof( g_tracker_id ) );

    peer->tracker_id = tracker_id;
    PROXYPEER_SETCONNECTED( peer->state );

    break;
close_socket:
    io_close( peersocket );
    PROXYPEER_SETDISCONNECTED( peer->state );
    break;
  case FLAG_CONNECTED:
    
    break;

  }
}

/* Can write new sync data to the stream */
static void handle_write( int64 peersocket ) {
  proxy_peer *peer = io_getcookie( peersocket );
  if( !peer ) { 
    /* Can't happen ;) */
    close( peersocket );
    return;
  }

  switch( peer->state & FLAG_MASK ) {
  case FLAG_DISCONNECTED: break; /* Shouldnt happen */
  case FLAG_CONNECTING:
    io_trywrite( peersocket, (void*)&g_tracker_id, sizeof( g_tracker_id ) );
    PROXYPEER_SETWAITTRACKERID( peer->state );
    io_dontwantwrite( peersocket );
    io_wantread( peersocket );
    break;
  case FLAG_CONNECTED:
    switch( iob_send( peersocket, &peer->outdata ) ) {
    case 0: /* all data sent */
      io_dontwantwrite( peersocket );
      break;
    case -3: /* an error occured */
      io_close( peersocket );
      PROXYPEER_SETDISCONNECTED( peer->state );
      iob_reset( &peer->outdata );
      free( peer->indata );
    default: /* Normal operation or eagain */
      break;
    }
    break;
  default:
    break;
  }

  return;
}

static void server_mainloop() {
  int64 sock;
  tai6464 now;

  while(1) {
    /* See, if we need to connect to anyone */
    if( time(NULL) > g_connection_reconn )
      handle_reconnects( );

    /* Wait for io events until next approx reconn check time */
    taia_now( &now );
    taia_addsec( &now, &now, 30 );
    io_waituntil( now );

    /* Loop over readable sockets */
    while( ( sock = io_canread( ) ) != -1 ) {
      const void *cookie = io_getcookie( sock );
      if( (uintptr_t)cookie == FLAG_SERVERSOCKET )
        handle_accept( sock );
      else
        handle_read( sock );
    }

    /* Loop over writable sockets */
    while( ( sock = io_canwrite( ) ) != -1 )
      handle_write( sock );
  }
}

int main( int argc, char **argv ) {
  static pthread_t sync_in_thread_id;
  static pthread_t sync_out_thread_id;
  ot_ip6 serverip;
  uint16_t tmpport;
  int scanon = 1, bound = 0;

  srandom( time(NULL) );
  g_tracker_id = random();

  while( scanon ) {
    switch( getopt( argc, argv, ":i:p:vh" ) ) {
    case -1: scanon = 0; break;
    case 'S': 
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
  pthread_create( &sync_in_thread_id, NULL, livesync_worker, NULL );
  pthread_create( &sync_out_thread_id, NULL, streamsync_worker, NULL );

  server_mainloop();
  return 0;
}

static void * streamsync_worker( void * args ) {
  (void)args;
  while( 1 ) {
    int bucket;
    /* For each bucket... */
    for( bucket=0; bucket<OT_BUCKET_COUNT; ++bucket ) {
      /* Get exclusive access to that bucket */
      ot_vector *torrents_list = mutex_bucket_lock( bucket );
      size_t tor_offset, count_def = 0, count_one = 0, count_two = 0, count_peers = 0;
      size_t mem, mem_a = 0, mem_b = 0;
      uint8_t *ptr, *ptr_a, *ptr_b, *ptr_c;

      /* For each torrent in this bucket.. */
      for( tor_offset=0; tor_offset<torrents_list->size; ++tor_offset ) {
        /* Address torrents members */
        ot_peerlist *peer_list = ( ((ot_torrent*)(torrents_list->data))[tor_offset] ).peer_list;
        switch( peer_list->peer_count ) {
          case 2: count_two++; break;
          case 1: count_one++; break;
          case 0: break;
          default:
            count_peers += peer_list->peer_count;
            count_def   += 1 + ( peer_list->peer_count >> 8 );
        }
      }

      /* Maximal memory requirement: max 3 blocks, max torrents * 20 + max peers * 7 */
      mem = 3 * ( 4 + 1 + 1 + 2 ) + ( count_one + count_two ) * 19 + count_def * 20 +
            ( count_one + 2 * count_two + count_peers ) * 7;

      ptr = ptr_a = ptr_b = ptr_c = malloc( mem );
      if( !ptr ) goto unlock_continue;

      if( count_one > 8 ) {
        mem_a = 4 + 1 + 1 + 2 + count_one * ( 19 + 7 );
        ptr_b += mem_a; ptr_c += mem_a;
        memcpy( ptr_a, &g_tracker_id, sizeof(g_tracker_id)); /* Offset 0: the tracker ID */
        ptr_a[4] = 1;                                       /* Offset 4: packet type 1 */
        ptr_a[5] = (bucket << 8) >> OT_BUCKET_COUNT_BITS;   /* Offset 5: the shared prefix */
        ptr_a[6] = count_one >> 8;
        ptr_a[7] = count_one & 255;
        ptr_a += 8;
      } else {
        count_def   += count_one;
        count_peers += count_one;
      }

      if( count_two > 8 ) {
        mem_b = 4 + 1 + 1 + 2 + count_two * ( 19 + 14 );
        ptr_c += mem_b;
        memcpy( ptr_b, &g_tracker_id, sizeof(g_tracker_id)); /* Offset 0: the tracker ID */
        ptr_b[4] = 2;                                       /* Offset 4: packet type 2 */
        ptr_b[5] = (bucket << 8) >> OT_BUCKET_COUNT_BITS;   /* Offset 5: the shared prefix */
        ptr_b[6] = count_two >> 8;
        ptr_b[7] = count_two & 255;
        ptr_b += 8;
      } else {
        count_def   += count_two;
        count_peers += 2 * count_two;
      }

      if( count_def ) {
        memcpy( ptr_c, &g_tracker_id, sizeof(g_tracker_id)); /* Offset 0: the tracker ID */
        ptr_c[4] = 0;                                       /* Offset 4: packet type 0 */
        ptr_c[5] = (bucket << 8) >> OT_BUCKET_COUNT_BITS;   /* Offset 5: the shared prefix */
        ptr_c[6] = count_def >> 8;
        ptr_c[7] = count_def & 255;
        ptr_c += 8;
      }

      /* For each torrent in this bucket.. */
      for( tor_offset=0; tor_offset<torrents_list->size; ++tor_offset ) {
        /* Address torrents members */
        ot_torrent *torrent = ((ot_torrent*)(torrents_list->data)) + tor_offset;
        ot_peerlist *peer_list = torrent->peer_list;
        ot_peer *peers = (ot_peer*)(peer_list->peers.data);
        uint8_t **dst;
        int multi = 0;
        switch( peer_list->peer_count ) {
          case 0:  continue;
          case 1:  dst = mem_a ? &ptr_a : &ptr_c; break;
          case 2:  dst = mem_b ? &ptr_b : &ptr_c; break;
          default: dst = &ptr_c; multi = 1; break;
        }

        do {
          size_t i, pc = peer_list->peer_count;
          if( pc > 255 ) pc = 255;
          memcpy( *dst, torrent->hash + 1, sizeof( ot_hash ) - 1);
          *dst += sizeof( ot_hash ) - 1;
          if( multi ) *(*dst)++ = pc;
          for( i=0; i < pc; ++i ) {
            memcpy( *dst, peers++, OT_IP_SIZE + 3 );
            *dst += OT_IP_SIZE + 3;
          }
          peer_list->peer_count -= pc; 
        } while( peer_list->peer_count );
        free_peerlist(peer_list);
      }

      free( torrents_list->data );
      memset( torrents_list, 0, sizeof(*torrents_list ) );
unlock_continue:
      mutex_bucket_unlock( bucket, 0 );

      if( ptr ) {
        int i;

        if( ptr_b > ptr_c ) ptr_c = ptr_b;
        if( ptr_a > ptr_c ) ptr_c = ptr_a;
        mem = ptr_c - ptr;

        for( i=0; i<g_connection_count; ++i ) {
          if( g_connections[i].fd != -1 ) {
            void *tmp = malloc( mem );
            if( tmp )
              if( !iob_addbuf_free( &g_connections[i].outdata, tmp, mem ) )
                free( tmp );
          }
        }

        free( ptr );
      }
      usleep( OT_SYNC_SLEEP );
    }
  }
  return 0;
}

static void * livesync_worker( void * args ) {
  (void)args;
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
  }
  return 0;
}
