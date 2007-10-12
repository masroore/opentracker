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
#include <pwd.h>

#include "trackerlogic.h"
#include "scan_urlencoded_query.h"

/* Globals */
static unsigned long long ot_overall_tcp_connections = 0;
static unsigned long long ot_overall_udp_connections = 0;
static unsigned long long ot_overall_tcp_successfulannounces = 0;
static unsigned long long ot_overall_udp_successfulannounces = 0;
static time_t ot_start_time;
static const size_t SUCCESS_HTTP_HEADER_LENGTH = 80;
static const size_t SUCCESS_HTTP_SIZE_OFF = 17;
static char g_adminip[4] = {0,0,0,0};

#if defined ( WANT_BLACKLISTING ) && defined (WANT_CLOSED_TRACKER )
  #error WANT_BLACKLISTING and WANT_CLOSED_TRACKER are exclusive.
#endif
#if defined ( WANT_BLACKLISTING ) || defined (WANT_CLOSED_TRACKER )
static char *accesslist_filename = NULL;
#define WANT_ACCESS_CONTROL
#endif

/* To always have space for error messages ;) */

static char static_inbuf[8192];
static char static_outbuf[8192];

static char *FLAG_TCP = "TCP";
static char *FLAG_UDP = "UDP";
static size_t ot_sockets_count = 0;

#ifdef _DEBUG_HTTPERROR
static char debug_request[8192];
#endif

struct http_data {
  union {
    array    request;
    io_batch batch;
  };
  unsigned char ip[4];
  int        blessed;
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
static void handle_udp4( const int64 serversocket );

static void ot_try_bind( char ip[4], uint16 port, int is_tcp );

static void usage( char *name );
static void help( char *name );

static void carp( const char *routine );
static void panic( const char *routine );
static void graceful( int s );

#define HTTPERROR_400         return httperror( s, "400 Invalid Request",       "This server only understands GET." )
#define HTTPERROR_400_PARAM   return httperror( s, "400 Invalid Request",       "Invalid parameter" )
#define HTTPERROR_400_COMPACT return httperror( s, "400 Invalid Request",       "This server only delivers compact results." )
#define HTTPERROR_403_IP      return httperror( s, "403 Access Denied",         "Your ip address is not allowed to administrate this server." )
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
  if( ( written_size < 0 ) || ( (size_t)written_size == size ) ) {
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
  struct http_data* h = io_getcookie( s );
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

/******************************
 *         S Y N C            *
 ******************************/
  case 4: /* sync ? */
    if( byte_diff( data, 4, "sync") ) HTTPERROR_404;
    if( !h->blessed ) HTTPERROR_403_IP;

    mode = SYNC_OUT;
    scanon = 1;

    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: scanon = 0; break;   /* TERMINATOR */
      case -1: HTTPERROR_400_PARAM; /* PARSE ERROR */
      default: scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE ); break;
      case 9:
        if(byte_diff(data,9,"changeset")) {
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          continue;
        }
        /* ignore this, when we dont at least see "d4:syncdee" */
        if( ( len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) ) < 10 ) HTTPERROR_400_PARAM;
        if( add_changeset_to_tracker( (ot_byte*)data, len ) ) HTTPERROR_400_PARAM;
        mode = SYNC_IN;
        break;
      }
    }

    if( mode == SYNC_OUT ) {
      if( !( reply_size = return_changeset_for_tracker( &reply ) ) ) HTTPERROR_500;
      return sendmallocdata( s, reply, reply_size );
    }

    /* Simple but proof for now */
    reply = "OK";
    reply_size = 2;

    break;
/******************************
 *        S T A T S           *
 ******************************/
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
        else if( !byte_diff(data,4,"tcp4"))
          mode = STATS_TCP;
        else if( !byte_diff(data,4,"udp4"))
          mode = STATS_UDP;
        else if( !byte_diff(data,4,"s24s"))
          mode = STATS_SLASH24S;
        else if( !byte_diff(data,4,"s24S"))
          mode = STATS_SLASH24S_OLD;
        else
          HTTPERROR_400_PARAM;
      }
    }

      switch( mode)
      {
        case STATS_DMEM:
          if( !( reply_size = return_memstat_for_tracker( &reply ) ) ) HTTPERROR_500;
          return sendmallocdata( s, reply, reply_size );
          
        case STATS_UDP:
          t = time( NULL ) - ot_start_time;
          reply_size = sprintf( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH,
                "%llu\n%llu\n%i seconds (%i hours)\nopentracker udp4 stats.",
                ot_overall_udp_connections, ot_overall_udp_successfulannounces, (int)t, (int)(t / 3600) );
          break;

        case STATS_TCP:
          t = time( NULL ) - ot_start_time;
          reply_size = sprintf( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH,
                "%llu\n%llu\n%i seconds (%i hours)\nopentracker tcp4 stats.",
                ot_overall_tcp_connections, ot_overall_tcp_successfulannounces, (int)t, (int)(t / 3600) );
          break;

        default:
        case STATS_MRTG:
          /* Enough for http header + whole scrape string */
          if( !( reply_size = return_stats_for_tracker( SUCCESS_HTTP_HEADER_LENGTH + static_outbuf, mode ) ) ) HTTPERROR_500;
          break;
        case STATS_SLASH24S:
{
          ot_dword diff; struct timeval tv1, tv2; gettimeofday( &tv1, NULL );
          if( !( reply_size = return_stats_for_slash24s( SUCCESS_HTTP_HEADER_LENGTH + static_outbuf, 25, 16 ) ) ) HTTPERROR_500;
          gettimeofday( &tv2, NULL ); diff = ( tv2.tv_sec - tv1.tv_sec ) * 1000000 + tv2.tv_usec - tv1.tv_usec;
          reply_size += sprintf( SUCCESS_HTTP_HEADER_LENGTH + static_outbuf + reply_size, "Time taken: %u\n", diff );
          break;
}
        case STATS_SLASH24S_OLD:
{
          ot_dword diff; struct timeval tv1, tv2; gettimeofday( &tv1, NULL );
          if( !( reply_size = return_stats_for_slash24s_old( SUCCESS_HTTP_HEADER_LENGTH + static_outbuf, 25, 16 ) ) ) HTTPERROR_500;
          gettimeofday( &tv2, NULL ); diff = ( tv2.tv_sec - tv1.tv_sec ) * 1000000 + tv2.tv_usec - tv1.tv_usec;
          reply_size += sprintf( SUCCESS_HTTP_HEADER_LENGTH + static_outbuf + reply_size, "Time taken: %u\n", diff );
          break;
}
      }
    break;

/******************************
 *       S C R A P E          *
 ******************************/
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
        hash = (ot_hash*)data;
        break;
      }
    }

    /* Scanned whole query string, no hash means full scrape... you might want to limit that */
    if( !hash ) {
      if( !( reply_size = return_fullscrape_for_tracker( &reply ) ) ) HTTPERROR_500;
      ot_overall_tcp_successfulannounces++;
      return sendmallocdata( s, reply, reply_size );
    }

    /* Enough for http header + whole scrape string */
    if( !( reply_size = return_tcp_scrape_for_torrent( hash, SUCCESS_HTTP_HEADER_LENGTH + static_outbuf ) ) ) HTTPERROR_500;

    ot_overall_tcp_successfulannounces++;
    break;
/******************************
 *      A N N O U N C E       *
 ******************************/
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
    if( OT_FLAG( &peer ) & PEER_FLAG_STOPPED )
      reply_size = remove_peer_from_torrent( hash, &peer, SUCCESS_HTTP_HEADER_LENGTH + static_outbuf, 1 );
    else {
      torrent = add_peer_to_torrent( hash, &peer, 0 );
      if( !torrent || !( reply_size = return_peers_for_torrent( torrent, numwant, SUCCESS_HTTP_HEADER_LENGTH + static_outbuf, 1 ) ) ) HTTPERROR_500;
    }
    ot_overall_tcp_successfulannounces++;
    break;
  case 10:
    if( byte_diff( data, 10, "scrape.php" ) ) HTTPERROR_404;
    goto SCRAPE_WORKAROUND;
  case 11:
    if( byte_diff( data, 11, "mrtg_scrape" ) ) HTTPERROR_404;

    t = time( NULL ) - ot_start_time;
    reply_size = sprintf( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH,
                          "%llu\n%llu\n%i seconds (%i hours)\nopentracker - Pretuned by german engineers, currently handling %llu connections per second.",
                          ot_overall_tcp_connections+ot_overall_udp_connections, ot_overall_tcp_successfulannounces+ot_overall_udp_successfulannounces, (int)t, (int)(t / 3600), (ot_overall_tcp_connections+ot_overall_udp_connections) / ( (unsigned int)t ? (unsigned int)t : 1 ) );
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
     plus dynamic space needed to expand our Content-Length value. We reserve SUCCESS_HTTP_SIZE_OFF for its expansion and calculate
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
  fprintf( stderr, "Usage: %s [-i ip] [-p port] [-P port] [-d dir] [-A ip]"
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
    return httperror( clientsocket, "500 Server Error", "Request too long.");

  if( ( !h->blessed ) && ( array_bytes( &h->request ) > 8192 ) )
    return httperror( clientsocket, "500 request too long", "You sent too much headers");

  if( memchr( array_start( &h->request ), '\n', array_length( &h->request, 1 ) ) )
    return httpresponse( clientsocket, array_start( &h->request ) );
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

    byte_zero( h, sizeof( struct http_data ) );
    memmove( h->ip, ip, sizeof( ip ) );

    if( !byte_diff( &h->ip, 4, g_adminip ) )
      h->blessed = 1;

    io_setcookie( i, h );

    ++ot_overall_tcp_connections;

    taia_now( &t );
    taia_addsec( &t, &t, OT_CLIENT_TIMEOUT );
    io_timeout( i, t );
  }

  if( errno == EAGAIN )
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

/* UDP implementation according to http://xbtt.sourceforge.net/udp_tracker_protocol.html */

static void handle_udp4( int64 serversocket ) {
  ot_peer     peer;
  ot_torrent *torrent;
  ot_hash    *hash = NULL;
  char        remoteip[4];
  ot_dword   *inpacket = (ot_dword*)static_inbuf;
  ot_dword   *outpacket = (ot_dword*)static_outbuf;
  ot_dword    numwant, left, event;
  ot_word     port, remoteport;
  size_t      r, r_out;

  r = socket_recv4( serversocket, static_inbuf, 8192, remoteip, &remoteport);

  ot_overall_udp_connections++;

  /* Minimum udp tracker packet size, also catches error */
  if( r < 16 )
    return;

  /* look for udp bittorrent magic id */
  if( (ntohl(inpacket[0]) != 0x00000417) || (ntohl(inpacket[1]) != 0x27101980) )
    return;

  switch( ntohl( inpacket[2] ) ) {
    case 0: /* This is a connect action */
      outpacket[0] = 0;           outpacket[1] = inpacket[3];
      outpacket[2] = inpacket[0]; outpacket[3] = inpacket[1];
      socket_send4( serversocket, static_outbuf, 16, remoteip, remoteport );
      ot_overall_udp_successfulannounces++;
      break;
    case 1: /* This is an announce action */
      /* Minimum udp announce packet size */
      if( r < 98 )
        return;

      numwant = 200;
      /* We do only want to know, if it is zero */
      left  = inpacket[64/4] | inpacket[68/4];

      event = ntohl( inpacket[80/4] );
      port  = *(ot_word*)( static_inbuf + 96 );
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
        torrent = add_peer_to_torrent( hash, &peer, 0 );
        if( !torrent )
          return; /* XXX maybe send error */

        r = 8 + return_peers_for_torrent( torrent, numwant, static_outbuf + 8, 0 );
      }

      socket_send4( serversocket, static_outbuf, r, remoteip, remoteport );
      ot_overall_udp_successfulannounces++;
      break;

    case 2: /* This is a scrape action */
      outpacket[0] = htonl( 2 );    /* scrape action */
      outpacket[1] = inpacket[12/4];

      for( r_out = 0; ( r_out * 20 < r - 16) && ( r_out <= 74 ); r_out++ )
        return_udp_scrape_for_torrent( (ot_hash*)( static_inbuf + 16 + 20 * r_out ), static_outbuf + 8 + 12 * r_out );

      socket_send4( serversocket, static_outbuf, 8 + 12 * r_out, remoteip, remoteport );
      ot_overall_udp_successfulannounces++;
      break;
  }
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
      const void *cookie = io_getcookie( i );
      if( cookie == FLAG_TCP )
        handle_accept( i );
      else if( cookie == FLAG_UDP )
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

    /* See if we need to move our pools */
    clean_all_torrents();
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

  ++ot_sockets_count;
}

#ifdef WANT_ACCESS_CONTROL
/* Read initial access list */
void read_accesslist_file( int foo ) {
  FILE *  accesslist_filehandle;
  ot_hash infohash;
  foo = foo;

  accesslist_filehandle = fopen( accesslist_filename, "r" );

  /* Free accesslist vector in trackerlogic.c*/
  accesslist_reset();

  if( accesslist_filehandle == NULL ) {
    fprintf( stderr, "Warning: Can't open accesslist file: %s (but will try to create it later, if necessary and possible).", accesslist_filename );
    return;
  }

  /* We do ignore anything that is not of the form "^[:xdigit:]{40}[^:xdigit:].*" */
  while( fgets( static_inbuf, sizeof(static_inbuf), accesslist_filehandle ) ) {
    int i;
    for( i=0; i<20; ++i ) {
      int eger = 16 * scan_fromhex( static_inbuf[ 2*i ] ) + scan_fromhex( static_inbuf[ 1 + 2*i ] );
      if( eger < 0 )
        goto ignore_line;
      infohash[i] = eger;
    }
    if( scan_fromhex( static_inbuf[ 40 ] ) >= 0 )
      goto ignore_line;

    /* Append accesslist to accesslist vector */
    accesslist_addentry( &infohash );

ignore_line:
    continue;
  }

  fclose( accesslist_filehandle );
}
#endif

int main( int argc, char **argv ) {
  struct passwd *pws = NULL;
  char serverip[4] = {0,0,0,0};
  char *serverdir = ".";
  int scanon = 1;

  while( scanon ) {
    switch( getopt( argc, argv, ":i:p:A:P:d:"
#ifdef WANT_BLACKLISTING
"b:"
#elif defined( WANT_CLOSED_TRACKER )
"w:"
#endif
    "h" ) ) {
      case -1 : scanon = 0; break;
      case 'i': scan_ip4( optarg, serverip ); break;
      case 'A': scan_ip4( optarg, g_adminip ); break;
#ifdef WANT_BLACKLISTING
      case 'b': accesslist_filename = optarg; break;
#elif defined( WANT_CLOSED_TRACKER )
      case 'w': accesslist_filename = optarg; break;
#endif
      case 'p': ot_try_bind( serverip, (uint16)atol( optarg ), 1 ); break;
      case 'P': ot_try_bind( serverip, (uint16)atol( optarg ), 0 ); break;
      case 'd': serverdir = optarg; break;
      case 'h': help( argv[0] ); exit( 0 );
      default:
      case '?': usage( argv[0] ); exit( 1 );
    }
  }

  /* Bind to our default tcp/udp ports */
  if( !ot_sockets_count ) {
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

#ifdef WANT_ACCESS_CONTROL
  /* Passing "0" since read_blacklist_file also is SIGHUP handler */
  if( accesslist_filename ) {
    read_accesslist_file( 0 );
    signal( SIGHUP,  read_accesslist_file );
  }
#endif

  signal( SIGPIPE, SIG_IGN );
  signal( SIGINT,  graceful );
  signal( SIGALRM, SIG_IGN );

  if( init_logic( serverdir ) == -1 )
    panic( "Logic not started" );

  ot_start_time = time( NULL );

  server_mainloop( );

  return 0;
}
