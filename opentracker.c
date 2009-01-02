/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.
   Some of the stuff below is stolen from Fefes example libowfat httpd.

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
#include "ip4.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_http.h"
#include "ot_udp.h"
#include "ot_accesslist.h"
#include "ot_stats.h"
#include "ot_livesync.h"

/* Globals */
time_t       g_now_seconds;
char *       g_redirecturl = NULL;
uint32_t     g_tracker_id;
volatile int g_opentracker_running = 1;

static char * g_serverdir = NULL;

/* To always have space for error messages ;) */
static char static_inbuf[8192];

static void panic( const char *routine ) {
  fprintf( stderr, "%s: %s\n", routine, strerror(errno) );
  exit( 111 );
}

static void signal_handler( int s ) {
  if( s == SIGINT ) {
    signal( SIGINT, SIG_IGN);
    g_opentracker_running = 0;

    trackerlogic_deinit();
    exit( 0 );
  } else if( s == SIGALRM ) {
    g_now_seconds = time(NULL);
    alarm(5);
  }
}

static void usage( char *name ) {
  fprintf( stderr, "Usage: %s [-i ip] [-p port] [-P port] [-r redirect] [-d dir] [-A ip] [-f config] [-s livesyncport]"
#ifdef WANT_ACCESSLIST_BLACK
  " [-b blacklistfile]"
#elif defined ( WANT_ACCESSLIST_WHITE )
  " [-w whitelistfile]"
#endif
  "\n", name );
}

#define HELPLINE(opt,desc) fprintf(stderr, "\t%-10s%s\n",opt,desc)
static void help( char *name ) {
  usage( name );

  HELPLINE("-f config","include and execute the config file");
  HELPLINE("-i ip","specify ip to bind to (default: *, you may specify more than one)");
  HELPLINE("-p port","specify tcp port to bind to (default: 6969, you may specify more than one)");
  HELPLINE("-P port","specify udp port to bind to (default: 6969, you may specify more than one)");
  HELPLINE("-r redirecturl","specify url where / should be redirected to (default none)");
  HELPLINE("-d dir","specify directory to try to chroot to (default: \".\")");
  HELPLINE("-A ip","bless an ip address as admin address (e.g. to allow syncs from this address)");
#ifdef WANT_ACCESSLIST_BLACK
  HELPLINE("-b file","specify blacklist file.");
#elif defined( WANT_ACCESSLIST_WHITE )
  HELPLINE("-w file","specify whitelist file.");
#endif

  fprintf( stderr, "\nExample:   ./opentracker -i 127.0.0.1 -p 6969 -P 6969 -f ./opentracker.conf -i 10.1.1.23 -p 2710 -p 80\n" );
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

  if( array_bytes( &h->request ) > 8192 )
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
    WRITE32(h->ip,0,READ32(ip,0));

    stats_issue_event( EVENT_ACCEPT, FLAG_TCP, ntohl(*(uint32_t*)ip));

    /* That breaks taia encapsulation. But there is no way to take system
       time this often in FreeBSD and libowfat does not allow to set unix time */
    taia_uint( &t, 0 ); /* Clear t */
    tai_unix( &(t.sec), (g_now_seconds + OT_CLIENT_TIMEOUT) );
    io_timeout( i, t );
  }

  if( errno == EAGAIN )
    io_eagain( serversocket );
}

static void server_mainloop( ) {
  time_t        next_timeout_check = g_now_seconds + OT_CLIENT_TIMEOUT_CHECKINTERVAL;
  struct        iovec *iovector;
  int           iovec_entries;

  for( ; ; ) {
    int64 i;

    io_wait();

    while( ( i = io_canread( ) ) != -1 ) {
      const void *cookie = io_getcookie( i );
      if( (intptr_t)cookie == FLAG_TCP )
        handle_accept( i );
      else if( (intptr_t)cookie == FLAG_UDP )
        handle_udp4( i );
      else
        handle_read( i );
    }

    while( ( i = mutex_workqueue_popresult( &iovec_entries, &iovector ) ) != -1 )
      http_sendiovecdata( i, iovec_entries, iovector );

    while( ( i = io_canwrite( ) ) != -1 )
      handle_write( i );

    if( g_now_seconds > next_timeout_check ) {
      while( ( i = io_timeouted() ) != -1 )
        handle_dead( i );
      next_timeout_check = g_now_seconds + OT_CLIENT_TIMEOUT_CHECKINTERVAL;
    }

    livesync_ticker();

    /* Enforce setting the clock */
    signal_handler( SIGALRM );
  }
}

static int64_t ot_try_bind( char ip[4], uint16_t port, PROTO_FLAG proto ) {
  int64 s = proto == FLAG_TCP ? socket_tcp4( ) : socket_udp4( );

#ifdef _DEBUG
  char *protos[] = {"TCP","UDP","UDP mcast"};
  uint8_t *_ip = (uint8_t *)ip;
  fprintf( stderr, "Binding socket type %s to address %d.%d.%d.%d:%d...", protos[proto],_ip[0],_ip[1],_ip[2],_ip[3],port);
#endif

  if( socket_bind4_reuse( s, ip, port ) == -1 )
    panic( "socket_bind4_reuse" );

  if( ( proto == FLAG_TCP ) && ( socket_listen( s, SOMAXCONN) == -1 ) )
    panic( "socket_listen" );

  if( !io_fd( s ) )
    panic( "io_fd" );

  io_setcookie( s, (void*)proto );

  io_wantread( s );

#ifdef _DEBUG
  fputs( " success.\n", stderr);
#endif

  return s;
}

char * set_config_option( char **option, char *value ) {
#ifdef _DEBUG
  fprintf( stderr, "Setting config option: %s\n", value );
#endif
  while( isspace(*value) ) ++value;
  free( *option );
  return *option = strdup( value );
}

static int scan_ip4_port( const char *src, char *ip, uint16 *port ) {
  const char *s = src;
  int off;
  while( isspace(*s) ) ++s;
  if( !(off = scan_ip4( s, ip ) ) )
    return 0;
  s += off;
  if( *s == 0 || isspace(*s)) return s-src;
  if( *(s++) != ':' )
    return 0;
  if( !(off = scan_ushort (s, port ) ) )
     return 0;
  return off+s-src;
}

int parse_configfile( char * config_filename ) {
  FILE *  accesslist_filehandle;
  char    inbuf[512], tmpip[4];
  int     bound = 0;

  accesslist_filehandle = fopen( config_filename, "r" );

  if( accesslist_filehandle == NULL ) {
    fprintf( stderr, "Warning: Can't open config file: %s.", config_filename );
    return 0;
  }

  while( fgets( inbuf, sizeof(inbuf), accesslist_filehandle ) ) {
    char *newl;
    char *p = inbuf;

    /* Skip white spaces */
    while(isspace(*p)) ++p;

    /* Ignore comments and empty lines */
    if((*p=='#')||(*p=='\n')||(*p==0)) continue;

    /* chomp */
    if(( newl = strchr(p, '\n' ))) *newl = 0;

    /* Scan for commands */
    if(!byte_diff(p,15,"tracker.rootdir" ) && isspace(p[15])) {
      set_config_option( &g_serverdir, p+16 );
    } else if(!byte_diff(p,14,"listen.tcp_udp" ) && isspace(p[14])) {
      uint16_t tmpport = 6969;
      if( !scan_ip4_port( p+15, tmpip, &tmpport )) goto parse_error;
      ot_try_bind( tmpip, tmpport, FLAG_TCP ); ++bound;
      ot_try_bind( tmpip, tmpport, FLAG_UDP ); ++bound;
    } else if(!byte_diff(p,10,"listen.tcp" ) && isspace(p[10])) {
      uint16_t tmpport = 6969;
      if( !scan_ip4_port( p+11, tmpip, &tmpport )) goto parse_error;
      ot_try_bind( tmpip, tmpport, FLAG_TCP );
      ++bound;
    } else if(!byte_diff(p, 10, "listen.udp" ) && isspace(p[10])) {
      uint16_t tmpport = 6969;
      if( !scan_ip4_port( p+11, tmpip, &tmpport )) goto parse_error;
      ot_try_bind( tmpip, tmpport, FLAG_UDP );
      ++bound;
#ifdef WANT_ACCESSLIST_WHITE
    } else if(!byte_diff(p, 16, "access.whitelist" ) && isspace(p[16])) {
      set_config_option( &g_accesslist_filename, p+17 );
#elif defined( WANT_ACCESSLIST_BLACK )
    } else if(!byte_diff(p, 16, "access.blacklist" ) && isspace(p[16])) {
      set_config_option( &g_accesslist_filename, p+17 );
#endif
#ifdef WANT_RESTRICT_STATS
    } else if(!byte_diff(p, 12, "access.stats" ) && isspace(p[12])) {
      if( !scan_ip4( p+13, tmpip )) goto parse_error;
      accesslist_blessip( tmpip, OT_PERMISSION_MAY_STAT );
#endif
    } else if(!byte_diff(p, 20, "tracker.redirect_url" ) && isspace(p[20])) {
      set_config_option( &g_redirecturl, p+21 );
#ifdef WANT_SYNC_LIVE
    } else if(!byte_diff(p, 24, "livesync.cluster.node_ip" ) && isspace(p[24])) {
      if( !scan_ip4( p+25, tmpip )) goto parse_error;
      accesslist_blessip( tmpip, OT_PERMISSION_MAY_LIVESYNC );
    } else if(!byte_diff(p, 23, "livesync.cluster.listen" ) && isspace(p[23])) {
      uint16_t tmpport = LIVESYNC_PORT;
      if( !scan_ip4_port( p+24, tmpip, &tmpport )) goto parse_error;
      livesync_bind_mcast( tmpip, tmpport );
#endif
    } else
      fprintf( stderr, "Unhandled line in config file: %s\n", inbuf );
    continue;
  parse_error:
      fprintf( stderr, "Parse error in config file: %s\n", inbuf);
  }
  fclose( accesslist_filehandle );
  return bound;
}

int drop_privileges (const char * const serverdir) {
  struct passwd *pws = NULL;

  /* Grab pws entry before chrooting */
  pws = getpwnam( "nobody" );
  endpwent();

  if( geteuid() == 0 ) {
    /* Running as root: chroot and drop privileges */
    if(chroot( serverdir )) {
      fprintf( stderr, "Could not chroot to %s, because: %s\n", serverdir, strerror(errno) );
      return -1;
    }

    if(chdir("/"))
      panic("chdir() failed after chrooting: ");

    if( !pws ) {
      setegid( (gid_t)-2 ); setgid( (gid_t)-2 );
      setuid( (uid_t)-2 );  seteuid( (uid_t)-2 );
    }
    else {
      setegid( pws->pw_gid ); setgid( pws->pw_gid );
      setuid( pws->pw_uid );  seteuid( pws->pw_uid );
    }

    if( geteuid() == 0 || getegid() == 0 )
      panic("Still running with root privileges?!");
  }
  else {
    /* Normal user, just chdir() */
    if(chdir( serverdir )) {
      fprintf( stderr, "Could not chroot to %s, because: %s\n", serverdir, strerror(errno) );
      return -1;
    }
  }

  return 0;
}

int main( int argc, char **argv ) {
  char serverip[4] = {0,0,0,0}, tmpip[4];
  int bound = 0, scanon = 1;
  uint16_t tmpport;

while( scanon ) {
    switch( getopt( argc, argv, ":i:p:A:P:d:r:s:f:v"
#ifdef WANT_ACCESSLIST_BLACK
"b:"
#elif defined( WANT_ACCESSLIST_WHITE )
"w:"
#endif
    "h" ) ) {
      case -1 : scanon = 0; break;
      case 'i':
        if( !scan_ip4( optarg, serverip )) { usage( argv[0] ); exit( 1 ); }
        break;
#ifdef WANT_ACCESSLIST_BLACK
      case 'b': set_config_option( &g_accesslist_filename, optarg); break;
#elif defined( WANT_ACCESSLIST_WHITE )
      case 'w': set_config_option( &g_accesslist_filename, optarg); break;
#endif
      case 'p':
        if( !scan_ushort( optarg, &tmpport)) { usage( argv[0] ); exit( 1 ); }
        ot_try_bind( serverip, tmpport, FLAG_TCP ); bound++; break;
      case 'P':
        if( !scan_ushort( optarg, &tmpport)) { usage( argv[0] ); exit( 1 ); }
        ot_try_bind( serverip, tmpport, FLAG_UDP ); bound++; break;
#ifdef WANT_SYNC_LIVE
      case 's':
        if( !scan_ushort( optarg, &tmpport)) { usage( argv[0] ); exit( 1 ); }
        livesync_bind_mcast( serverip, tmpport); break;
#endif
      case 'd': set_config_option( &g_serverdir, optarg ); break;
      case 'r': set_config_option( &g_redirecturl, optarg ); break;
      case 'A':
        if( !scan_ip4( optarg, tmpip )) { usage( argv[0] ); exit( 1 ); }
        accesslist_blessip( tmpip, 0xffff ); /* Allow everything for now */
        break;
      case 'f': bound += parse_configfile( optarg ); break;
      case 'h': help( argv[0] ); exit( 0 );
      case 'v': stats_return_tracker_version( static_inbuf ); fputs( static_inbuf, stderr ); exit( 0 );
      default:
      case '?': usage( argv[0] ); exit( 1 );
    }
  }

  /* Bind to our default tcp/udp ports */
  if( !bound) {
    ot_try_bind( serverip, 6969, FLAG_TCP );
    ot_try_bind( serverip, 6969, FLAG_UDP );
  }

  if( drop_privileges( g_serverdir ? g_serverdir : "." ) == -1 )
    panic( "drop_privileges failed, exiting. Last error");

  signal( SIGPIPE, SIG_IGN );
  signal( SIGINT,  signal_handler );
  signal( SIGALRM, signal_handler );

  g_now_seconds = time( NULL );

  /* Init all sub systems. This call may fail with an exit() */
  trackerlogic_init( );

  /* Kick off our initial clock setting alarm */
  alarm(5);

  server_mainloop( );

  return 0;
}

const char *g_version_opentracker_c = "$Source$: $Revision$\n";
