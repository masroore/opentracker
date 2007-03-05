/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.
   Some of the stuff below is stolen from Fefes example libowfat httpd.
*/

#include "socket.h"
#include "io.h"
#include "iob.h"
#include "buffer.h"
#include "array.h"
#include "byte.h"
#include "case.h"
#include "fmt.h"
#include "str.h"
#include "scan.h"
#include "ip4.h"
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>

#include "trackerlogic.h"
#include "scan_urlencoded_query.h"

/* Globals */
static unsigned int ot_overall_connections = 0;
static unsigned int ot_overall_successfulannounces = 0;
static time_t ot_start_time;
static const size_t SUCCESS_HTTP_HEADER_LENGTH = 80;
static const size_t SUCCESS_HTTP_SIZE_OFF = 17;

/* To always have space for error messages ;) */

static char static_inbuf[8192];
static char static_outbuf[8192];

#define OT_MAXSOCKETS_TCP4 64
#define OT_MAXSOCKETS_UDP4 64
static int64 ot_sockets_tcp4[ OT_MAXSOCKETS_TCP4 ];
static int64 ot_sockets_udp4[ OT_MAXSOCKETS_UDP4 ];
static int ot_sockets_tcp4_count = 0;
static int ot_sockets_udp4_count = 0;

#ifdef _DEBUG_HTTPERROR
static char debug_request[8192];
#endif

struct http_data {
  union {
    array    request;
    io_batch batch;
  };
  unsigned char ip[4];
};

/* Prototypes */

int main( int argc, char **argv );

static void httperror( const int64 s, const char *title, const char *message );
static void httpresponse( const int64 s, char *data );

static void sendmallocdata( const int64 s, char *buffer, const size_t size );
static void senddata( const int64 s, char *buffer, const size_t size );

static void server_mainloop( );
static void handle_timeouted( void );
static void handle_accept( const int64 serversocket );
static void handle_read( const int64 clientsocket );
static void handle_write( const int64 clientsocket );

static void usage( char *name );
static void help( char *name );

static void carp( const char *routine );
static void panic( const char *routine );
static void graceful( int s );

#define HTTPERROR_400         return httperror( s, "400 Invalid Request",       "This server only understands GET." )
#define HTTPERROR_400_PARAM   return httperror( s, "400 Invalid Request",       "Invalid parameter" )
#define HTTPERROR_400_COMPACT return httperror( s, "400 Invalid Request",       "This server only delivers compact results." )
#define HTTPERROR_404         return httperror( s, "404 Not Found",             "No such file or directory." )
#define HTTPERROR_500         return httperror( s, "500 Internal Server Error", "A server error has occured. Please retry later." )

/* End of prototypes */

static void carp( const char *routine ) {
  buffer_puts( buffer_2, routine );
  buffer_puts( buffer_2, ": " );
  buffer_puterror( buffer_2 );
  buffer_putnlflush( buffer_2 );
}

static void panic( const char *routine ) {
  carp( routine );
  exit( 111 );
}

static void httperror( const int64 s, const char *title, const char *message ) {
  size_t reply_size = sprintf( static_outbuf, "HTTP/1.0 %s\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: %zd\r\n\r\n<title>%s</title>\n",
                        title, strlen(message)+strlen(title)+16-4,title+4);
#ifdef _DEBUG_HTTPERROR
  fprintf( stderr, "DEBUG: invalid request was: %s\n", debug_request );
#endif
  senddata(s,static_outbuf,reply_size);
}

static void sendmallocdata( const int64 s, char *buffer, size_t size ) {
  struct http_data *h = io_getcookie( s );
  char *header;
  size_t header_size;
  tai6464 t;

  if( !h )
    return free( buffer );
  array_reset( &h->request );

  header = malloc( SUCCESS_HTTP_HEADER_LENGTH );
  if( !header ) {
    free( buffer );
    HTTPERROR_500;
  }

  header_size = sprintf( header, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r\n", size );

  iob_reset( &h->batch );
  iob_addbuf_free( &h->batch, header, header_size );
  iob_addbuf_free( &h->batch, buffer, size );

  /* writeable sockets just have a tcp timeout */
  taia_uint( &t, 0 ); io_timeout( s, t );
  io_dontwantread( s );
  io_wantwrite( s );
}

static void senddata( const int64 s, char *buffer, size_t size ) {
  struct http_data *h = io_getcookie( s );
  ssize_t written_size;

  /* whoever sends data is not interested in its input-array */
  if( h )
    array_reset( &h->request );

  written_size = write( s, buffer, size );
  if( ( written_size < 0 ) || ( written_size == size ) ) {
    free( h ); io_close( s );
  } else {
    char * outbuf = malloc( size - written_size );
    tai6464 t;

    if( !outbuf ) {
      free(h); io_close( s );
      return;
    }

    iob_reset( &h->batch );
    memmove( outbuf, buffer + written_size, size - written_size );
    iob_addbuf_free( &h->batch, outbuf, size - written_size );

    /* writeable sockets just have a tcp timeout */
    taia_uint( &t, 0 ); io_timeout( s, t );
    io_dontwantread( s );
    io_wantwrite( s );
  }
}

static void httpresponse( const int64 s, char *data ) {
  char       *c, *reply;
  ot_peer     peer;
  ot_torrent *torrent;
  ot_hash    *hash = NULL;
  int         numwant, tmp, scanon, mode;
  unsigned short port = htons(6881);
  time_t      t;
  ssize_t     len;
  size_t      reply_size = 0, reply_off;

#ifdef _DEBUG_HTTPERROR
  memcpy( debug_request, data, sizeof( debug_request ) );
#endif

  /* This one implicitely tests strlen < 5, too -- remember, it is \n terminated */
  if( byte_diff( data, 5, "GET /") ) HTTPERROR_400;

  /* Query string MUST terminate with SP -- we know that theres at least a '\n' where this search terminates */
  for( c = data + 5; *c!=' ' && *c != '\t' && *c != '\n' && *c != '\r'; ++c ) ;
  if( *c != ' ' ) HTTPERROR_400;

  /* Skip leading '/' */
  for( c = data+4; *c == '/'; ++c);

  switch( scan_urlencoded_query( &c, data = c, SCAN_PATH ) ) {
  case 4: /* sync ? */
    if( byte_diff( data, 4, "sync") ) HTTPERROR_404;
    scanon = 1;

    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: scanon = 0; break;   /* TERMINATOR */
      case -1: HTTPERROR_400_PARAM; /* PARSE ERROR */
      case 9:
        if(byte_diff(data,9,"info_hash")) {
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          continue;
        }
        /* ignore this, when we have less than 20 bytes */
        if( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) != 20 ) HTTPERROR_400_PARAM;
        hash = (ot_hash*)data; /* Fall through intended */
        break;
      default:
        scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
        break;
      }
    }

    if( !hash ) HTTPERROR_400_PARAM;
    if( !( reply_size = return_sync_for_torrent( hash, &reply ) ) ) HTTPERROR_500;

    return sendmallocdata( s, reply, reply_size );
  case 5: /* stats ? */
    if( byte_diff(data,5,"stats")) HTTPERROR_404;
    scanon = 1;
    mode = STATS_MRTG;

    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: scanon = 0; break;   /* TERMINATOR */
      case -1: HTTPERROR_400_PARAM; /* PARSE ERROR */
      default: scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE ); break;
      case 4:
        if( byte_diff(data,4,"mode")) {
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          continue;
        }
        if( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) != 4 ) HTTPERROR_400_PARAM;
        if( !byte_diff(data,4,"mrtg"))
          mode = STATS_MRTG;
        else if( !byte_diff(data,4,"top5"))
          mode = STATS_TOP5;
        else if( !byte_diff(data,4,"dmem"))
          mode = STATS_DMEM;
        else
          HTTPERROR_400_PARAM;
      }
    }

    if( mode == STATS_DMEM ) {
      if( !( reply_size = return_memstat_for_tracker( &reply ) ) ) HTTPERROR_500;
      return sendmallocdata( s, reply, reply_size );
    }

    /* Enough for http header + whole scrape string */
    if( !( reply_size = return_stats_for_tracker( SUCCESS_HTTP_HEADER_LENGTH + static_outbuf, mode ) ) ) HTTPERROR_500;
    break;
  case 6: /* scrape ? */
    if( byte_diff( data, 6, "scrape") ) HTTPERROR_404;

SCRAPE_WORKAROUND:

    scanon = 1;
    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: scanon = 0; break;   /* TERMINATOR */
      case -1: HTTPERROR_400_PARAM; /* PARSE ERROR */
      default: scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE ); break;
      case 9:
        if(byte_diff(data,9,"info_hash")) {
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          continue;
        }
        /* ignore this, when we have less than 20 bytes */
        if( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) != 20 ) HTTPERROR_400_PARAM;
        hash = (ot_hash*)data; /* Fall through intended */
        break;
      }
    }

    /* Scanned whole query string, no hash means full scrape... you might want to limit that */
    if( !hash ) {
      if( !( reply_size = return_fullscrape_for_tracker( &reply ) ) ) HTTPERROR_500;
      ot_overall_successfulannounces++;
      return sendmallocdata( s, reply, reply_size );
    }

    /* Enough for http header + whole scrape string */
    if( !( reply_size = return_scrape_for_torrent( hash, SUCCESS_HTTP_HEADER_LENGTH + static_outbuf ) ) ) HTTPERROR_500;

    ot_overall_successfulannounces++;
    break;
  case 8:
    if( byte_diff( data, 8, "announce" ) ) HTTPERROR_404;

ANNOUNCE_WORKAROUND:

    OT_SETIP( &peer, ((struct http_data*)io_getcookie( s ) )->ip );
    OT_SETPORT( &peer, &port );
    OT_FLAG( &peer ) = 0;
    numwant = 50;
    scanon = 1;

    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: scanon = 0; break;   /* TERMINATOR */
      case -1: HTTPERROR_400_PARAM; /* PARSE ERROR */
      default: scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE ); break;
#ifdef WANT_IP_FROM_QUERY_STRING
      case 2:
        if(!byte_diff(data,2,"ip")) {
          unsigned char ip[4];
          len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          if( ( len <= 0 ) || scan_fixed_ip( data, len, ip ) ) HTTPERROR_400_PARAM;
          OT_SETIP( &peer, ip );
       } else
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
       break;
#endif
      case 4:
        if( !byte_diff( data, 4, "port" ) ) {
          len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          if( ( len <= 0 ) || scan_fixed_int( data, len, &tmp ) || ( tmp > 0xffff ) ) HTTPERROR_400_PARAM;
          port = htons( tmp ); OT_SETPORT( &peer, &port );
        } else if( !byte_diff( data, 4, "left" ) ) {
          if( ( len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) ) <= 0 ) HTTPERROR_400_PARAM;
          if( scan_fixed_int( data, len, &tmp ) ) tmp = 0;
          if( !tmp ) OT_FLAG( &peer ) |= PEER_FLAG_SEEDING;
        } else
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
        break;
      case 5:
        if( byte_diff( data, 5, "event" ) )
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
        else switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) ) {
        case -1:
          HTTPERROR_400_PARAM;
        case 7:
          if( !byte_diff( data, 7, "stopped" ) ) OT_FLAG( &peer ) |= PEER_FLAG_STOPPED;
          break;
        case 9:
          if( !byte_diff( data, 9, "completed" ) ) OT_FLAG( &peer ) |= PEER_FLAG_COMPLETED;
        default: /* Fall through intended */
          break;
        }
        break;
      case 7:
        if(!byte_diff(data,7,"numwant")) {
          len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          if( ( len <= 0 ) || scan_fixed_int( data, len, &numwant ) ) HTTPERROR_400_PARAM;
          if( numwant > 200 ) numwant = 200;
        } else if(!byte_diff(data,7,"compact")) {
          len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          if( ( len <= 0 ) || scan_fixed_int( data, len, &tmp ) ) HTTPERROR_400_PARAM;
          if( !tmp ) HTTPERROR_400_COMPACT;
        } else
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
        break;
      case 9:
        if(byte_diff(data,9,"info_hash")) {
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          continue;
        }
        /* ignore this, when we have less than 20 bytes */
        if( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) != 20 ) HTTPERROR_400_PARAM;
        hash = (ot_hash*)data;
        break;
      }
    }

    /* Scanned whole query string */
    if( !hash ) {
      reply_size = sprintf( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH, "d14:failure reason81:Your client forgot to send your torrent's info_hash. Please upgrade your client.e" );
      break;
    }
    if( OT_FLAG( &peer ) & PEER_FLAG_STOPPED ) {
      remove_peer_from_torrent( hash, &peer );
      reply_size = sprintf( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH, "d8:completei0e10:incompletei0e8:intervali%ie5:peers0:e", OT_CLIENT_REQUEST_INTERVAL_RANDOM );
    } else {
      torrent = add_peer_to_torrent( hash, &peer );
      if( !torrent || !( reply_size = return_peers_for_torrent( torrent, numwant, SUCCESS_HTTP_HEADER_LENGTH + static_outbuf ) ) ) HTTPERROR_500;
    }
    ot_overall_successfulannounces++;
    break;
  case 10:
    if( byte_diff( data, 10, "scrape.php" ) ) HTTPERROR_404;
    goto SCRAPE_WORKAROUND;
  case 11:
    if( byte_diff( data, 11, "mrtg_scrape" ) ) HTTPERROR_404;

    t = time( NULL ) - ot_start_time;
    reply_size = sprintf( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH,
                          "%i\n%i\n%i seconds (%i hours)\nopentracker - Pretuned by german engineers, currently handling %i connections per second.",
                          ot_overall_connections, ot_overall_successfulannounces, (int)t, (int)(t / 3600), (int)ot_overall_connections / ( (int)t ? (int)t : 1 ) );
    break;
  case 12:
    if( byte_diff( data, 12, "announce.php" ) ) HTTPERROR_404;
    goto ANNOUNCE_WORKAROUND;
  default: /* neither *scrape nor announce */
    HTTPERROR_404;
  }

  if( !reply_size ) HTTPERROR_500;

  /* This one is rather ugly, so I take you step by step through it.

     1. In order to avoid having two buffers, one for header and one for content, we allow all above functions from trackerlogic to
     write to a fixed location, leaving SUCCESS_HTTP_HEADER_LENGTH bytes in our static buffer, which is enough for the static string
     plus dynamic space needed to expand our Content-Length value. We reserve SUCCESS_HTTP_SIZE_OFF for it expansion and calculate
     the space NOT needed to expand in reply_off
  */
  reply_off = SUCCESS_HTTP_SIZE_OFF - snprintf( static_outbuf, 0, "%zd", reply_size );

  /* 2. Now we sprintf our header so that sprintf writes its terminating '\0' exactly one byte before content starts. Complete
     packet size is increased by size of header plus one byte '\n', we  will copy over '\0' in next step */
  reply_size += 1 + sprintf( static_outbuf + reply_off, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r", reply_size );

  /* 3. Finally we join both blocks neatly */
  static_outbuf[ SUCCESS_HTTP_HEADER_LENGTH - 1 ] = '\n';

  senddata( s, static_outbuf + reply_off, reply_size );
}

static void graceful( int s ) {
  if( s == SIGINT ) {
    signal( SIGINT, SIG_IGN);
    deinit_logic();
    exit( 0 );
  }
}

static void usage( char *name ) {
  fprintf( stderr, "Usage: %s [-i serverip] [-p serverport] [-d serverdirectory]"
#ifdef WANT_CLOSED_TRACKER
  " [-oc]"
#endif
#ifdef WANT_BLACKLIST
  " [-bB]"
#endif
  "\n", name );
}

static void help( char *name ) {
  usage( name );
  fprintf( stderr, "\t-i serverip\tspecify ip to bind to (default: *, you may specify more than one)\n"
                   "\t-p serverport\tspecify port to bind to (default: 6969, you may specify more than one)\n"
                   "\t-P serverport\tspecify port to bind to (you may specify more than one)\n"
                   "\t-d serverdir\tspecify directory containing white- or black listed torrent info_hashes (default: \".\")\n"
#ifdef WANT_CLOSED_TRACKER
                   "\t-o\t\tmake tracker an open tracker, e.g. do not check for white list (default: off)\n"
                   "\t-c\t\tmake tracker a closed tracker, e.g. check each announced torrent against white list (default: on)\n"
#endif
#ifdef WANT_BLACKLIST
                   "\t-b\t\tmake tracker check its black list, e.g. check each announced torrent against black list (default: on)\n"
                   "\t-B\t\tmake tracker check its black list, e.g. check each announced torrent against black list (default: off)\n"
#endif
#ifdef WANT_CLOSED_TRACKER
                   "\n* To white list a torrent, touch a file inside serverdir with info_hash hex string.\n"
#endif
#ifdef WANT_BLACKLIST
#ifndef WANT_CLOSED_TRACKER
                   "\n"
#endif
                   "* To white list a torrent, touch a file inside serverdir with info_hash hex string, preprended by '-'.\n"
#endif
                   "\nExample:   ./opentracker -i 127.0.0.1 -p 6968 -P 6968 -i 10.1.1.23 -p 6969 -p 6970\n"
);
}

static void handle_read( const int64 clientsocket ) {
  struct http_data* h = io_getcookie( clientsocket );
  ssize_t l;

  if( ( l = io_tryread( clientsocket, static_inbuf, sizeof static_inbuf ) ) <= 0 ) {
    if( h ) {
      array_reset( &h->request );
      free( h );
    }
    io_close( clientsocket );
    return;
  }

#ifdef _DEBUG_HTTPERROR
  memcpy( debug_request, "500!\0", 5 );
#endif

  /* If we get the whole request in one packet, handle it without copying */
  if( !array_start( &h->request ) ) {
    if( memchr( static_inbuf, '\n', l ) )
      return httpresponse( clientsocket, static_inbuf );
    return array_catb( &h->request, static_inbuf, l );
  }

  array_catb( &h->request, static_inbuf, l );

  if( array_failed( &h->request ) )
    httperror( clientsocket, "500 Server Error", "Request too long.");
  else if( array_bytes( &h->request ) > 8192 )
    httperror( clientsocket, "500 request too long", "You sent too much headers");
  else if( memchr( array_start( &h->request ), '\n', array_length( &h->request, 1 ) ) )
    httpresponse( clientsocket, array_start( &h->request ) );
}

static void handle_write( const int64 clientsocket ) {
  struct http_data* h=io_getcookie( clientsocket );
  if( !h || ( iob_send( clientsocket, &h->batch ) <= 0 ) ) {
    iob_reset( &h->batch );
    io_close( clientsocket );
    free( h );
  }
}

static void handle_accept( const int64 serversocket ) {
  struct http_data *h;
  unsigned char ip[4];
  uint16 port;
  tai6464 t;
  int64 i;

  while( ( i = socket_accept4( serversocket, (char*)ip, &port) ) != -1 ) {

    if( !io_fd( i ) ||
        !( h = (struct http_data*)malloc( sizeof( struct http_data ) ) ) ) {
      io_close( i );
      continue;
    }

    io_wantread( i );

    byte_zero(h,sizeof(struct http_data));
    memmove(h->ip,ip,sizeof(ip));
    io_setcookie(i,h);
    ++ot_overall_connections;
    taia_now(&t);
    taia_addsec(&t,&t,OT_CLIENT_TIMEOUT);
    io_timeout(i,t);
  }

  if( errno==EAGAIN )
    io_eagain( serversocket );
}

static void handle_timeouted( void ) {
  int64 i;
  while( ( i = io_timeouted() ) != -1 ) {
    struct http_data* h=io_getcookie( i );
    if( h ) {
      array_reset( &h->request );
      free( h );
    }
    io_close(i);
  }
}

void handle_udp4( int64 serversocket ) {
  size_t r;
  char remoteip[4];
  uint16 port;

  r = socket_recv4(serversocket, static_inbuf, 8192, remoteip, &port);

  // too lazy :)
}

int ot_in_tcp4_sockets( int64 fd ) {
  int i;
  for( i=0; i<ot_sockets_tcp4_count; ++i)
    if( ot_sockets_tcp4[i] == fd )
      return 1;
  return 0;
}

int ot_in_udp4_sockets( int64 fd ) {
  int i;
  for( i=0; i<ot_sockets_udp4_count; ++i)
    if( ot_sockets_udp4[i] == fd )
      return 1;
  return 0;
}

static void server_mainloop( ) {
  tai6464 t, next_timeout_check;

  taia_now( &next_timeout_check );

  for( ; ; ) {
    int64 i;

    taia_now( &t );
    taia_addsec( &t, &t, OT_CLIENT_TIMEOUT_CHECKINTERVAL );
    io_waituntil( t );

    while( ( i = io_canread( ) ) != -1 ) {
      if( ot_in_tcp4_sockets( i ) )
        handle_accept( i );
      else if( ot_in_udp4_sockets( i ) )
        handle_udp4( i );
      else
        handle_read( i );
    }

    while( ( i = io_canwrite( ) ) != -1 )
      handle_write( i );

    taia_now( &t );
    if( taia_less( &next_timeout_check, &t ) ) {
      handle_timeouted( );
      taia_now( &next_timeout_check );
      taia_addsec( &next_timeout_check, &next_timeout_check, OT_CLIENT_TIMEOUT_CHECKINTERVAL);
    }
  }
}

void ot_try_bind_tcp4( char ip[4], uint16 port ) {
  int64 s = socket_tcp4( );
  if( ot_sockets_tcp4_count == OT_MAXSOCKETS_TCP4 ) {
    fprintf( stderr, "Too many tcp4 sockets, increase OT_MAXSOCKETS_TCP4 and recompile.\n"); exit(1);
  }
  if( socket_bind4_reuse( s, ip, port ) == -1 )
    panic( "socket_bind4_reuse" );

  if( socket_listen( s, SOMAXCONN) == -1 )
    panic( "socket_listen" );

  if( !io_fd( s ) )
    panic( "io_fd" );

  io_wantread( s );

  ot_sockets_tcp4[ ot_sockets_tcp4_count++ ] = s;
}

void ot_try_bind_udp4( char ip[4], uint16 port ) {
  int64 s = socket_udp4( );
  if( ot_sockets_udp4_count == OT_MAXSOCKETS_UDP4 ) {
    fprintf( stderr, "Too many udp4 sockets, increase OT_MAXSOCKETS_UDP4 and recompile.\n"); exit(1);
  }
  if( socket_bind4_reuse( s, ip, port ) == -1 )
    panic( "socket_bind4_reuse" );

  if( !io_fd( s ) )
    panic( "io_fd" );

  io_wantread( s );

  ot_sockets_udp4[ ot_sockets_udp4_count++ ] = s;
}

int main( int argc, char **argv ) {
  char serverip[4] = {0,0,0,0};
  char *serverdir = ".";
  int scanon = 1;

  while( scanon ) {
    switch( getopt( argc, argv, ":i:p:d:ocbBh" ) ) {
      case -1 : scanon = 0; break;
      case 'i': scan_ip4( optarg, serverip ); break;
      case 'p': ot_try_bind_tcp4( serverip, (uint16)atol( optarg ) ); break;
      case 'P': ot_try_bind_udp4( serverip, (uint16)atol( optarg ) ); break;
      case 'd': serverdir = optarg; break;
      case 'h': help( argv[0] ); exit( 0 );
#ifdef WANT_CLOSED_TRACKER
      case 'o': g_closedtracker = 0; break;
      case 'c': g_closedtracker = 1; break;
#endif
#ifdef WANT_BLACKLIST
      case 'b': g_check_blacklist = 1; break;
      case 'B': g_check_blacklist = 0; break;
#endif
      default:
      case '?': usage( argv[0] ); exit( 1 );
    }
  }

  // Bind to our default tcp port
  if( !ot_sockets_tcp4_count && !ot_sockets_udp4_count )
    ot_try_bind_tcp4( serverip, 6969 );

  setegid( (gid_t)-2 ); setuid( (uid_t)-2 );
  setgid( (gid_t)-2 ); seteuid( (uid_t)-2 );

  signal( SIGPIPE, SIG_IGN );
  signal( SIGINT,  graceful );
  if( init_logic( serverdir ) == -1 )
    panic( "Logic not started" );

  ot_start_time = time( NULL );

  server_mainloop( );

  return 0;
}
