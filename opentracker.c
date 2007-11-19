/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.
   Some of the stuff below is stolen from Fefes example libowfat httpd.
*/

/* System */
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <arpa/inet.h>
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
#include "buffer.h"
#include "array.h"
#include "byte.h"
#include "case.h"
#include "fmt.h"
#include "str.h"
#include "scan.h"
#include "ip4.h"

/* Opentracker */
#include "trackerlogic.h"
#include "scan_urlencoded_query.h"
#include "ot_stats.h"
#include "ot_sync.h"
#include "ot_udp.h"
#include "ot_fullscrape.h"
#include "ot_iovec.h"
#include "ot_accesslist.h"
#include "ot_mutex.h"
#include "ot_clean.h"

/* Globals */
static const size_t SUCCESS_HTTP_HEADER_LENGTH = 80;
static const size_t SUCCESS_HTTP_SIZE_OFF = 17;
static uint32_t g_adminip_addresses[OT_ADMINIP_MAX];
static unsigned int g_adminip_count = 0;
static time_t ot_last_clean_time;
time_t ot_start_time;
time_t g_now;

#ifndef WANT_TRACKER_SYNC
#define add_peer_to_torrent(A,B,C) add_peer_to_torrent(A,B)
#endif

#ifndef NO_FULLSCRAPE_LOGGING
#define LOG_TO_STDERR( ... ) fprintf( stderr, __VA_ARGS__ )
#else
#define LOG_TO_STDERR( ... )
#endif

/* To always have space for error messages ;) */
char static_inbuf[8192];
char static_outbuf[8192];

#define OT_MAXMULTISCRAPE_COUNT 64
static ot_hash multiscrape_buf[OT_MAXMULTISCRAPE_COUNT];

static char *FLAG_TCP = "TCP";
static char *FLAG_UDP = "UDP";
static size_t ot_sockets_count = 0;

#ifdef _DEBUG_HTTPERROR
static char debug_request[8192];
#define _DEBUG_HTTPERROR_PARAM( param ) , param
#else
#define _DEBUG_HTTPERROR_PARAM( param )
#endif

typedef enum {
  STRUCT_HTTP_FLAG_ARRAY_USED     = 1,
  STRUCT_HTTP_FLAG_IOB_USED       = 2,
  STRUCT_HTTP_FLAG_WAITINGFORTASK = 4
} STRUCT_HTTP_FLAG;

struct http_data {
  union {
    array          request;
    io_batch       batch;
  };
  unsigned char    ip[4];
  STRUCT_HTTP_FLAG flag;
};
#define NOTBLESSED( h ) (!bsearch( &h->ip, g_adminip_addresses, g_adminip_count, 4, ot_ip_compare ))
static int ot_ip_compare( const void *a, const void *b ) { return memcmp( a,b,4 ); }

/* Prototypes */

int main( int argc, char **argv );

static void httperror( const int64 s, const char *title, const char *message );
static void httpresponse( const int64 s, char *data _DEBUG_HTTPERROR_PARAM(size_t l ) );

static void sendmmapdata( const int64 s, char *buffer, const size_t size );
static void sendiovecdata( const int64 s, int iovec_entries, struct iovec *iovector );
static void senddata( const int64 s, char *buffer, const size_t size );

static void server_mainloop( );
static void handle_timeouted( void );
static void handle_accept( const int64 serversocket );
static void handle_read( const int64 clientsocket );
static void handle_write( const int64 clientsocket );

static void ot_try_bind( char ip[4], uint16 port, int is_tcp );

static void usage( char *name );
static void help( char *name );

static void carp( const char *routine );
static void panic( const char *routine );
static void signal_handler( int s );

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

static void sendmmapdata( const int64 s, char *buffer, size_t size ) {
  struct http_data *h = io_getcookie( s );
  char *header;
  size_t header_size;
  tai6464 t;

  if( !h ) {
    munmap( buffer, size );
    return;
  }
  if( h->flag & STRUCT_HTTP_FLAG_ARRAY_USED ) {
    h->flag &= ~STRUCT_HTTP_FLAG_ARRAY_USED;
    array_reset( &h->request );
  }

  header = malloc( SUCCESS_HTTP_HEADER_LENGTH );
  if( !header ) {
    munmap( buffer, size );
    HTTPERROR_500;
  }

  header_size = sprintf( header, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r\n", size );

  iob_reset( &h->batch );
  iob_addbuf_free( &h->batch, header, header_size );
  iob_addbuf_munmap( &h->batch, buffer, size );
  h->flag |= STRUCT_HTTP_FLAG_IOB_USED;

  /* writeable sockets timeout after twice the pool timeout
     which defaults to 5 minutes (e.g. after 10 minutes) */
  taia_now( &t ); taia_addsec( &t, &t, OT_CLIENT_TIMEOUT_SEND );
  io_timeout( s, t );
  io_dontwantread( s );
  io_wantwrite( s );
}

static void sendiovecdata( const int64 s, int iovec_entries, struct iovec *iovector ) {
  struct http_data *h = io_getcookie( s );
  char *header;
  int i;
  size_t header_size, size = iovec_length( &iovec_entries, &iovector );
  tai6464 t;

  /* No cookie? Bad socket. Leave. */
  if( !h ) {
    iovec_free( &iovec_entries, &iovector );
    HTTPERROR_500;
  }
  
  /* If this socket collected request in a buffer,
     free it now */
  if( h->flag & STRUCT_HTTP_FLAG_ARRAY_USED ) {
    h->flag &= ~STRUCT_HTTP_FLAG_ARRAY_USED;
    array_reset( &h->request );
  }

  /* If we came here, wait for the answer is over */
  h->flag &= ~STRUCT_HTTP_FLAG_WAITINGFORTASK;

  /* Our answers never are 0 bytes. Return an error. */
  if( !iovec_entries || !iovector[0].iov_len ) {
    iovec_free( &iovec_entries, &iovector );
    HTTPERROR_500;
  }

  /* Prepare space for http header */
  header = malloc( SUCCESS_HTTP_HEADER_LENGTH );
  if( !header ) {
    iovec_free( &iovec_entries, &iovector );
    HTTPERROR_500;
  }

  header_size = sprintf( header, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r\n", size );

  iob_reset( &h->batch );
  iob_addbuf_free( &h->batch, header, header_size );

  /* Will move to ot_iovec.c */
  for( i=0; i<iovec_entries; ++i )
    iob_addbuf_munmap( &h->batch, iovector[i].iov_base, iovector[i].iov_len );
  free( iovector );

  h->flag |= STRUCT_HTTP_FLAG_IOB_USED;

  /* writeable sockets timeout after twice the pool timeout
     which defaults to 5 minutes (e.g. after 10 minutes) */
  taia_now( &t ); taia_addsec( &t, &t, OT_CLIENT_TIMEOUT_SEND );
  io_timeout( s, t );
  io_dontwantread( s );
  io_wantwrite( s );
}

static void senddata( const int64 s, char *buffer, size_t size ) {
  struct http_data *h = io_getcookie( s );
  ssize_t written_size;

  /* whoever sends data is not interested in its input-array */
  if( h && ( h->flag & STRUCT_HTTP_FLAG_ARRAY_USED ) ) {
    h->flag &= ~STRUCT_HTTP_FLAG_ARRAY_USED;
    array_reset( &h->request );
  }

  written_size = write( s, buffer, size );
  if( ( written_size < 0 ) || ( (size_t)written_size == size ) ) {
    free( h ); io_close( s );
  } else {
    char * outbuf;
    tai6464 t;

    if( !h ) return;
    if( !( outbuf =  malloc( size - written_size ) ) ) {
      free(h); io_close( s );
      return;
    }

    iob_reset( &h->batch );
    memmove( outbuf, buffer + written_size, size - written_size );
    iob_addbuf_free( &h->batch, outbuf, size - written_size );
    h->flag |= STRUCT_HTTP_FLAG_IOB_USED;

    /* writeable short data sockets just have a tcp timeout */
    taia_uint( &t, 0 ); io_timeout( s, t );
    io_dontwantread( s );
    io_wantwrite( s );
  }
}

static void httpresponse( const int64 s, char *data _DEBUG_HTTPERROR_PARAM( size_t l ) ) {
  struct http_data* h = io_getcookie( s );
  char       *c;
  ot_peer     peer;
  ot_torrent *torrent;
  ot_hash    *hash = NULL;
  int         numwant, tmp, scanon, mode;
  ot_tasktype format = TASK_FULLSCRAPE;
  unsigned short port = htons(6881);
  ssize_t     len;
  size_t      reply_size = 0, reply_off;

#ifdef _DEBUG_HTTPERROR
  if( l >= sizeof( debug_request ) )
    l = sizeof( debug_request) - 1;
  memcpy( debug_request, data, l );
  debug_request[ l ] = 0;
#endif

  /* This one implicitely tests strlen < 5, too -- remember, it is \n terminated */
  if( byte_diff( data, 5, "GET /") ) HTTPERROR_400;

  /* Query string MUST terminate with SP -- we know that theres at least a '\n' where this search terminates */
  for( c = data + 5; *c!=' ' && *c != '\t' && *c != '\n' && *c != '\r'; ++c ) ;
  if( *c != ' ' ) HTTPERROR_400;

  /* Skip leading '/' */
  for( c = data+4; *c == '/'; ++c);

  switch( scan_urlencoded_query( &c, data = c, SCAN_PATH ) ) {
#ifdef WANT_TRACKER_SYNC
/******************************
 *         S Y N C            *
 ******************************/
  case 4: /* sync ? */
    if( *data == 'a' ) goto ANNOUNCE_WORKAROUND;
    if( !byte_diff( data, 2, "sc" ) ) goto SCRAPE_WORKAROUND;
    if( byte_diff( data, 4, "sync") ) HTTPERROR_404;
    if( NOTBLESSED( h ) ) HTTPERROR_403_IP;

LOG_TO_STDERR( "sync: %d.%d.%d.%d\n", h->ip[0], h->ip[1], h->ip[2], h->ip[3] );

    mode = SYNC_OUT;
    scanon = 1;

    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: scanon = 0; break;   /* TERMINATOR */
      case -1: HTTPERROR_400_PARAM; /* PARSE ERROR */
      default: scan_urlencoded_skipvalue( &c ); break;
      case 9:
        if(byte_diff(data,9,"changeset")) {
          scan_urlencoded_skipvalue( &c );
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
      char *reply;
      if( !( reply_size = return_changeset_for_tracker( &reply ) ) ) HTTPERROR_500;
      return sendmmapdata( s, reply, reply_size );
    }

    /* Simple but proof for now */
    memmove( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH, "OK", 2);
    reply_size = 2;

    break;
#endif
/******************************
 *        S T A T S           *
 ******************************/
  case 5: /* stats ? */
    if( *data == 'a' ) goto ANNOUNCE_WORKAROUND;
    if( !byte_diff( data, 2, "sc" ) ) goto SCRAPE_WORKAROUND;
    if( byte_diff(data,5,"stats")) HTTPERROR_404;
    scanon = 1;
    mode = TASK_STATS_PEERS;

    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: scanon = 0; break;   /* TERMINATOR */
      case -1: HTTPERROR_400_PARAM; /* PARSE ERROR */
      default: scan_urlencoded_skipvalue( &c ); break;
      case 4:
        if( byte_diff(data,4,"mode")) {
          scan_urlencoded_skipvalue( &c );
          continue;
        }
        if( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) != 4 ) HTTPERROR_400_PARAM;
        if( !byte_diff(data,4,"peer"))
          mode = TASK_STATS_PEERS;
        else if( !byte_diff(data,4,"conn"))
          mode = TASK_STATS_CONNS;
        else if( !byte_diff(data,4,"top5"))
          mode = TASK_STATS_TOP5;
        else if( !byte_diff(data,4,"fscr"))
          mode = TASK_STATS_FULLSCRAPE;
        else if( !byte_diff(data,4,"tcp4"))
          mode = TASK_STATS_TCP;
        else if( !byte_diff(data,4,"udp4"))
          mode = TASK_STATS_UDP;
        else if( !byte_diff(data,4,"s24s"))
          mode = TASK_STATS_SLASH24S;
        else if( !byte_diff(data,4,"tpbs"))
          mode = TASK_STATS_TPB;
        else
          HTTPERROR_400_PARAM;
        break;
      case 6:
        if( byte_diff(data,6,"format")) {
          scan_urlencoded_skipvalue( &c );
          continue;
        }
        if( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) != 3 ) HTTPERROR_400_PARAM;
        if( !byte_diff(data,3,"bin"))
          format = TASK_FULLSCRAPE_TPB_BINARY;
        else if( !byte_diff(data,3,"ben"))
          format = TASK_FULLSCRAPE;
        else if( !byte_diff(data,3,"url"))
          format = TASK_FULLSCRAPE_TPB_URLENCODED;
        else if( !byte_diff(data,3,"txt"))
          format = TASK_FULLSCRAPE_TPB_ASCII;
        else
          HTTPERROR_400_PARAM;
        break;
      }
    }

    if( mode == TASK_STATS_TPB ) {
      /* Pass this task to the worker thread */
      h->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK;
      fullscrape_deliver( s, format );
      io_dontwantread( s );
      return;
    }

    // default format for now
    if( !( reply_size = return_stats_for_tracker( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH, mode, 0 ) ) ) HTTPERROR_500;
    break;

/******************************
 *       S C R A P E          *
 ******************************/
  case 6: /* scrape ? */
    if( *data == 'a' ) goto ANNOUNCE_WORKAROUND;
    if( byte_diff( data, 6, "scrape") ) HTTPERROR_404;

    /* Full scrape... you might want to limit that */
    if( !byte_diff( data, 12, "scrape HTTP/" ) ) {
LOG_TO_STDERR( "[%08d] scrp: %d.%d.%d.%d - FULL SCRAPE\n", (unsigned int)(g_now - ot_start_time), h->ip[0], h->ip[1], h->ip[2], h->ip[3] );
#ifdef _DEBUG_HTTPERROR
write( 2, debug_request, l );
#endif
      /* Pass this task to the worker thread */
      h->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK;
      fullscrape_deliver( s, TASK_FULLSCRAPE );
      io_dontwantread( s );
      return;
    }

SCRAPE_WORKAROUND:

    /* This is to hack around stupid clients that send "scrape ?info_hash" */
    if( c[-1] != '?' ) {
      while( ( *c != '?' ) && ( *c != '\n' ) ) ++c;
      if( *c == '\n' ) HTTPERROR_400_PARAM;
      ++c;
    }

    scanon = 1;
    numwant = 0;
    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: scanon = 0; break;   /* TERMINATOR */
      case -1:
      if( numwant )
          goto UTORRENT1600_WORKAROUND;
        HTTPERROR_400_PARAM; /* PARSE ERROR */
      default: scan_urlencoded_skipvalue( &c ); break;
      case 9:
        if(byte_diff(data,9,"info_hash")) {
          scan_urlencoded_skipvalue( &c );
          continue;
        }
        /* ignore this, when we have less than 20 bytes */
        if( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) != (ssize_t)sizeof(ot_hash) ) {
#ifdef WANT_UTORRENT1600_WORKAROUND
          if( data[20] != '?' )
#endif
          HTTPERROR_400_PARAM;
        }
        if( numwant < OT_MAXMULTISCRAPE_COUNT )
          memmove( multiscrape_buf + numwant++, data, sizeof(ot_hash) );
        break;
      }
    }

UTORRENT1600_WORKAROUND:

    /* No info_hash found? Inform user */
    if( !numwant ) HTTPERROR_400_PARAM;

    /* Enough for http header + whole scrape string */
    if( !( reply_size = return_tcp_scrape_for_torrent( multiscrape_buf, numwant, SUCCESS_HTTP_HEADER_LENGTH + static_outbuf ) ) ) HTTPERROR_500;
    stats_issue_event( EVENT_SCRAPE, 1, reply_size );
    break;
/******************************
 *      A N N O U N C E       *
 ******************************/
  case 8:
    if( !byte_diff( data, 2, "sc" ) ) goto SCRAPE_WORKAROUND;
    if( *data != 'a' ) HTTPERROR_404;

ANNOUNCE_WORKAROUND:

    /* This is to hack around stupid clients that send "announce ?info_hash" */
    if( c[-1] != '?' ) {
      while( ( *c != '?' ) && ( *c != '\n' ) ) ++c;
      if( *c == '\n' ) HTTPERROR_400_PARAM;
      ++c;
    }

    OT_SETIP( &peer, ((struct http_data*)io_getcookie( s ) )->ip );
    OT_SETPORT( &peer, &port );
    OT_FLAG( &peer ) = 0;
    numwant = 50;
    scanon = 1;

    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: scanon = 0; break;   /* TERMINATOR */
      case -1: HTTPERROR_400_PARAM; /* PARSE ERROR */
      default: scan_urlencoded_skipvalue( &c ); break;
#ifdef WANT_IP_FROM_QUERY_STRING
      case 2:
        if(!byte_diff(data,2,"ip")) {
          unsigned char ip[4];
          len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          if( ( len <= 0 ) || scan_fixed_ip( data, len, ip ) ) HTTPERROR_400_PARAM;
          OT_SETIP( &peer, ip );
       } else
          scan_urlencoded_skipvalue( &c );
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
          scan_urlencoded_skipvalue( &c );
        break;
      case 5:
        if( byte_diff( data, 5, "event" ) )
          scan_urlencoded_skipvalue( &c );
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
          if( numwant < 0 ) numwant = 50;
          if( numwant > 200 ) numwant = 200;
        } else if(!byte_diff(data,7,"compact")) {
          len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          if( ( len <= 0 ) || scan_fixed_int( data, len, &tmp ) ) HTTPERROR_400_PARAM;
          if( !tmp ) HTTPERROR_400_COMPACT;
        } else
          scan_urlencoded_skipvalue( &c );
        break;
      case 9:
        if(byte_diff(data,9,"info_hash")) {
          scan_urlencoded_skipvalue( &c );
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
      if( !torrent || !( reply_size = return_peers_for_torrent( hash, numwant, SUCCESS_HTTP_HEADER_LENGTH + static_outbuf, 1 ) ) ) HTTPERROR_500;
    }
    stats_issue_event( EVENT_ANNOUNCE, 1, reply_size);
    break;
  default:
    if( ( *data == 'a' ) || ( *data == '?' ) ) goto ANNOUNCE_WORKAROUND;
    if( !byte_diff( data, 2, "sc" ) ) goto SCRAPE_WORKAROUND;
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

static void handle_read( const int64 clientsocket ) {
  struct http_data* h = io_getcookie( clientsocket );
  ssize_t l;

  if( ( l = io_tryread( clientsocket, static_inbuf, sizeof static_inbuf ) ) <= 0 )
    return handle_dead( clientsocket );

#ifdef _DEBUG_HTTPERROR
  memcpy( debug_request, "500!\0", 5 );
#endif

  /* If we get the whole request in one packet, handle it without copying */
  if( !array_start( &h->request ) ) {
    if( memchr( static_inbuf, '\n', l ) )
      return httpresponse( clientsocket, static_inbuf _DEBUG_HTTPERROR_PARAM( l ) );
    h->flag |= STRUCT_HTTP_FLAG_ARRAY_USED;
    return array_catb( &h->request, static_inbuf, l );
  }

  h->flag |= STRUCT_HTTP_FLAG_ARRAY_USED;
  array_catb( &h->request, static_inbuf, l );

  if( array_failed( &h->request ) )
    return httperror( clientsocket, "500 Server Error", "Request too long.");

  if( ( array_bytes( &h->request ) > 8192 ) && NOTBLESSED( h ) )
     return httperror( clientsocket, "500 request too long", "You sent too much headers");

  if( memchr( array_start( &h->request ), '\n', array_bytes( &h->request ) ) )
    return httpresponse( clientsocket, array_start( &h->request ) _DEBUG_HTTPERROR_PARAM( array_bytes( &h->request ) ) );
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

    if( !io_fd( i ) ||
        !( h = (struct http_data*)malloc( sizeof( struct http_data ) ) ) ) {
      io_close( i );
      continue;
    }
    io_setcookie( i, h );
    io_wantread( i );

    byte_zero( h, sizeof( struct http_data ) );
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

static void handle_timeouted( void ) {
  int64 i;
  while( ( i = io_timeouted() ) != -1 )
    handle_dead( i );
}

static void server_mainloop( ) {
  time_t next_timeout_check = g_now + OT_CLIENT_TIMEOUT_CHECKINTERVAL;
  struct iovec *iovector;
  int iovec_entries;

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
      sendiovecdata( i, iovec_entries, iovector );

    while( ( i = io_canwrite( ) ) != -1 )
      handle_write( i );

    if( g_now > next_timeout_check ) {
      handle_timeouted( );
      next_timeout_check = g_now + OT_CLIENT_TIMEOUT_CHECKINTERVAL;
    }

    /* See if we need to move our pools */
    if( g_now != ot_last_clean_time ) {
      ot_last_clean_time = g_now;
      clean_all_torrents();
    }
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

int main( int argc, char **argv ) {
  struct passwd *pws = NULL;
  char serverip[4] = {0,0,0,0};
  char *serverdir = ".";
  int scanon = 1;
#ifdef WANT_ACCESS_CONTROL
  char *accesslist_filename = NULL;
#endif

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
#ifdef WANT_BLACKLISTING
      case 'b': accesslist_filename = optarg; break;
#elif defined( WANT_CLOSED_TRACKER )
      case 'w': accesslist_filename = optarg; break;
#endif
      case 'p': ot_try_bind( serverip, (uint16)atol( optarg ), 1 ); break;
      case 'P': ot_try_bind( serverip, (uint16)atol( optarg ), 0 ); break;
      case 'd': serverdir = optarg; break;
      case 'A':
        if( g_adminip_count < OT_ADMINIP_MAX )
          scan_ip4( optarg, (char*)(g_adminip_addresses + g_adminip_count++) );
        break;
      case 'h': help( argv[0] ); exit( 0 );
      default:
      case '?': usage( argv[0] ); exit( 1 );
    }
  }

  /* Sort our admin ips for quick lookup */
  qsort( g_adminip_addresses, g_adminip_count, 4, ot_ip_compare );

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

  accesslist_init( accesslist_filename );

  signal( SIGPIPE, SIG_IGN );
  signal( SIGINT,  signal_handler );
  signal( SIGALRM, signal_handler );

  if( trackerlogic_init( serverdir ) == -1 )
    panic( "Logic not started" );

  g_now = ot_start_time = ot_last_clean_time = time( NULL );
  alarm(5);

  server_mainloop( );

  return 0;
}
