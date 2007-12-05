/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.
   Some of the stuff below is stolen from Fefes example libowfat httpd.
*/

/* System */
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <pwd.h>

/* Libowfat */
#include "socket.h"
#include "io.h"
#include "iob.h"
#include "array.h"
#include "fmt.h"
#include "scan.h"
#include "ip4.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_iovec.h"
#include "ot_mutex.h"
#include "ot_http.h"
#include "ot_udp.h"
#include "ot_clean.h"
#include "ot_accesslist.h"
#include "ot_stats.h"

/* Globals */
time_t g_now;
char * g_redirecturl = NULL;

/* To always have space for error messages ;) */
static char static_inbuf[8192];

static char *FLAG_TCP = "T";
static char *FLAG_UDP = "U";

static void panic( const char *routine ) {
  fprintf( stderr, "%s: %s\n", routine, strerror(errno) );
  exit( 111 );
}

static void signal_handler( int s ) {
  if( s == SIGINT ) {
    signal( SIGINT, SIG_IGN);

    trackerlogic_deinit();
    exit( 0 );
  } else if( s == SIGALRM ) {
    g_now = time(NULL);
    alarm(5);
  }
}

static void usage( char *name ) {
  fprintf( stderr, "Usage: %s [-i ip] [-p port] [-P port] [-r redirect] [-d dir] [-A ip]"
#ifdef WANT_BLACKLISTING
  " [-b blacklistfile]"
#elif defined ( WANT_CLOSED_TRACKER )
  " [-w whitelistfile]"
#endif
  "\n", name );
}

#define HELPLINE(opt,desc) fprintf(stderr, "\t%-10s%s\n",opt,desc)
static void help( char *name ) {
  usage( name );

  HELPLINE("-i ip","specify ip to bind to (default: *, you may specify more than one)");
  HELPLINE("-p port","specify tcp port to bind to (default: 6969, you may specify more than one)");
  HELPLINE("-P port","specify udp port to bind to (default: 6969, you may specify more than one)");
  HELPLINE("-r redirecturl","specify url where / should be redirected to (default none)");
  HELPLINE("-d dir","specify directory to try to chroot to (default: \".\")");
  HELPLINE("-A ip","bless an ip address as admin address (e.g. to allow syncs from this address)");
#ifdef WANT_BLACKLISTING
  HELPLINE("-b file","specify blacklist file.");
#elif defined( WANT_CLOSED_TRACKER )
  HELPLINE("-w file","specify whitelist file.");
#endif

  fprintf( stderr, "\nExample:   ./opentracker -i 127.0.0.1 -p 6969 -P 6969 -i 10.1.1.23 -p 2710 -p 80\n" );
}
#undef HELPLINE

static void handle_dead( const int64 socket ) {
  struct http_data* h=io_getcookie( socket );
  if( h ) {
    if( h->flag & STRUCT_HTTP_FLAG_IOB_USED )
      iob_reset( &h->batch );
    if( h->flag & STRUCT_HTTP_FLAG_ARRAY_USED )
      array_reset( &h->request );
    if( h->flag & STRUCT_HTTP_FLAG_WAITINGFORTASK )
      mutex_workqueue_canceltask( socket );
    free( h );
  }
  io_close( socket );
}

static ssize_t handle_read( const int64 clientsocket ) {
  struct http_data* h = io_getcookie( clientsocket );
  ssize_t l;

  if( ( l = io_tryread( clientsocket, static_inbuf, sizeof static_inbuf ) ) <= 0 ) {
    handle_dead( clientsocket );
    return 0;
  }

  /* If we get the whole request in one packet, handle it without copying */
  if( !array_start( &h->request ) ) {
    if( memchr( static_inbuf, '\n', l ) )
      return http_handle_request( clientsocket, static_inbuf, l );
    h->flag |= STRUCT_HTTP_FLAG_ARRAY_USED;
    array_catb( &h->request, static_inbuf, l );
    return 0;
  }

  h->flag |= STRUCT_HTTP_FLAG_ARRAY_USED;
  array_catb( &h->request, static_inbuf, l );

  if( array_failed( &h->request ) )
    return http_issue_error( clientsocket, CODE_HTTPERROR_500 );

  if( ( array_bytes( &h->request ) > 8192 ) && !accesslist_isblessed( (char*)&h->ip, OT_PERMISSION_MAY_SYNC ) )
     return http_issue_error( clientsocket, CODE_HTTPERROR_500 );

  if( memchr( array_start( &h->request ), '\n', array_bytes( &h->request ) ) )
    return http_handle_request( clientsocket, array_start( &h->request ), array_bytes( &h->request ) );

  return 0;
}

static void handle_write( const int64 clientsocket ) {
  struct http_data* h=io_getcookie( clientsocket );
  if( !h || ( iob_send( clientsocket, &h->batch ) <= 0 ) )
    handle_dead( clientsocket );
}

static void handle_accept( const int64 serversocket ) {
  struct http_data *h;
  unsigned char ip[4];
  uint16 port;
  tai6464 t;
  int64 i;

  while( ( i = socket_accept4( serversocket, (char*)ip, &port) ) != -1 ) {

    /* Put fd into a non-blocking mode */
    io_nonblock( i );

    if( !io_fd( i ) ||
        !( h = (struct http_data*)malloc( sizeof( struct http_data ) ) ) ) {
      io_close( i );
      continue;
    }
    io_setcookie( i, h );
    io_wantread( i );

    memset( h, 0, sizeof( struct http_data ) );
    memmove( h->ip, ip, sizeof( ip ) );

    stats_issue_event( EVENT_ACCEPT, 1, 0);

    /* That breaks taia encapsulation. But there is no way to take system
       time this often in FreeBSD and libowfat does not allow to set unix time */
    taia_uint( &t, 0 ); /* Clear t */
    tai_unix( &(t.sec), (g_now + OT_CLIENT_TIMEOUT) );
    io_timeout( i, t );
  }

  if( errno == EAGAIN )
    io_eagain( serversocket );
}

static void server_mainloop( ) {
  static time_t ot_last_clean_time;
  time_t        next_timeout_check = g_now + OT_CLIENT_TIMEOUT_CHECKINTERVAL;
  struct        iovec *iovector;
  int           iovec_entries;

  for( ; ; ) {
    int64 i;

    io_wait();

    while( ( i = io_canread( ) ) != -1 ) {
      const void *cookie = io_getcookie( i );
      if( cookie == FLAG_TCP )
        handle_accept( i );
      else if( cookie == FLAG_UDP )
        handle_udp4( i );
      else
        handle_read( i );
    }

    while( ( i = mutex_workqueue_popresult( &iovec_entries, &iovector ) ) != -1 )
      http_sendiovecdata( i, iovec_entries, iovector );

    while( ( i = io_canwrite( ) ) != -1 )
      handle_write( i );

    if( g_now > next_timeout_check ) {
      while( ( i = io_timeouted() ) != -1 )
        handle_dead( i );
      next_timeout_check = g_now + OT_CLIENT_TIMEOUT_CHECKINTERVAL;
    }

    /* See if we need to move our pools */
    if( NOW != ot_last_clean_time ) {
      ot_last_clean_time = NOW;
      clean_all_torrents();
    }

    /* Enforce setting the clock */
    signal_handler( SIGALRM );
  }
}

static void ot_try_bind( char ip[4], uint16 port, int is_tcp ) {
  int64 s = is_tcp ? socket_tcp4( ) : socket_udp4();

  if( socket_bind4_reuse( s, ip, port ) == -1 )
    panic( "socket_bind4_reuse" );

  if( is_tcp && ( socket_listen( s, SOMAXCONN) == -1 ) )
    panic( "socket_listen" );

  if( !io_fd( s ) )
    panic( "io_fd" );

  io_setcookie( s, is_tcp ? FLAG_TCP : FLAG_UDP );

  io_wantread( s );
}

int main( int argc, char **argv ) {
  struct passwd *pws = NULL;
  char serverip[4] = {0,0,0,0}, tmpip[4];
  char *serverdir = ".";
  int bound = 0, scanon = 1;
#ifdef WANT_ACCESS_CONTROL
  char *accesslist_filename = NULL;
#endif

  while( scanon ) {
    switch( getopt( argc, argv, ":i:p:A:P:d:r:"
#ifdef WANT_BLACKLISTING
"b:"
#elif defined( WANT_CLOSED_TRACKER )
"w:"
#endif
    "h" ) ) {
      case -1 : scanon = 0; break;
      case 'i': scan_ip4( optarg, serverip ); break;
#ifdef WANT_BLACKLISTING
      case 'b': accesslist_filename = optarg; break;
#elif defined( WANT_CLOSED_TRACKER )
      case 'w': accesslist_filename = optarg; break;
#endif
      case 'p': ot_try_bind( serverip, (uint16)atol( optarg ), 1 ); bound++; break;
      case 'P': ot_try_bind( serverip, (uint16)atol( optarg ), 0 ); bound++; break;
      case 'd': serverdir = optarg; break;
      case 'r': g_redirecturl = optarg; break;
      case 'A':
        scan_ip4( optarg, tmpip );
        accesslist_blessip( tmpip, 0xffff ); /* Allow everything for now */
        break;
      case 'h': help( argv[0] ); exit( 0 );
      default:
      case '?': usage( argv[0] ); exit( 1 );
    }
  }

  /* Bind to our default tcp/udp ports */
  if( !bound) {
    ot_try_bind( serverip, 6969, 1 );
    ot_try_bind( serverip, 6969, 0 );
  }

  /* Drop permissions */
  pws = getpwnam( "nobody" );
  if( !pws ) {
    setegid( (gid_t)-2 ); setuid( (uid_t)-2 );
    setgid( (gid_t)-2 ); seteuid( (uid_t)-2 );
  } else {
    setegid( pws->pw_gid ); setuid( pws->pw_uid );
    setgid( pws->pw_gid ); seteuid( pws->pw_uid );
  }
  endpwent();

  accesslist_init( accesslist_filename );

  signal( SIGPIPE, SIG_IGN );
  signal( SIGINT,  signal_handler );
  signal( SIGALRM, signal_handler );

  g_now = time( NULL );

  if( trackerlogic_init( serverdir ) == -1 )
    panic( "Logic not started" );

  alarm(5);

  server_mainloop( );

  return 0;
}
