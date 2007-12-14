/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

/* System */
#include <sys/types.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Libowfat */
#include "byte.h"
#include "array.h"
#include "iob.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_http.h"
#include "ot_iovec.h"
#include "scan_urlencoded_query.h"
#include "ot_fullscrape.h"
#include "ot_stats.h"
#include "ot_accesslist.h"
#include "ot_sync.h"

#ifndef WANT_TRACKER_SYNC
#define add_peer_to_torrent(A,B,C) add_peer_to_torrent(A,B)
#endif

#define OT_MAXMULTISCRAPE_COUNT 64
static ot_hash multiscrape_buf[OT_MAXMULTISCRAPE_COUNT];
extern char *g_redirecturl;

enum {
  SUCCESS_HTTP_HEADER_LENGTH = 80,
  SUCCESS_HTTP_HEADER_LENGHT_CONTENT_ENCODING = 32,
  SUCCESS_HTTP_SIZE_OFF = 17 };

/* Our static output buffer */
static char static_outbuf[8192];
#ifdef _DEBUG_HTTPERROR
static char debug_request[8192];
#endif

static void http_senddata( const int64 client_socket, char *buffer, size_t size ) {
  struct http_data *h = io_getcookie( client_socket );
  ssize_t written_size;

  /* whoever sends data is not interested in its input-array */
  if( h && ( h->flag & STRUCT_HTTP_FLAG_ARRAY_USED ) ) {
    h->flag &= ~STRUCT_HTTP_FLAG_ARRAY_USED;
    array_reset( &h->request );
  }

  written_size = write( client_socket, buffer, size );
  if( ( written_size < 0 ) || ( (size_t)written_size == size ) ) {
    free( h ); io_close( client_socket );
  } else {
    char * outbuf;
    tai6464 t;

    if( !h ) return;
    if( !( outbuf =  malloc( size - written_size ) ) ) {
      free(h); io_close( client_socket );
      return;
    }

    iob_reset( &h->batch );
    memmove( outbuf, buffer + written_size, size - written_size );
    iob_addbuf_free( &h->batch, outbuf, size - written_size );
    h->flag |= STRUCT_HTTP_FLAG_IOB_USED;

    /* writeable short data sockets just have a tcp timeout */
    taia_uint( &t, 0 ); io_timeout( client_socket, t );
    io_dontwantread( client_socket );
    io_wantwrite( client_socket );
  }
}

#define HTTPERROR_302         return http_issue_error( client_socket, CODE_HTTPERROR_302 )
#define HTTPERROR_400         return http_issue_error( client_socket, CODE_HTTPERROR_400 )
#define HTTPERROR_400_PARAM   return http_issue_error( client_socket, CODE_HTTPERROR_400_PARAM )
#define HTTPERROR_400_COMPACT return http_issue_error( client_socket, CODE_HTTPERROR_400_COMPACT )
#define HTTPERROR_403_IP      return http_issue_error( client_socket, CODE_HTTPERROR_403_IP )
#define HTTPERROR_404         return http_issue_error( client_socket, CODE_HTTPERROR_404 )
#define HTTPERROR_500         return http_issue_error( client_socket, CODE_HTTPERROR_500 )
ssize_t http_issue_error( const int64 client_socket, int code ) {
  char *error_code[] = { "302 Found", "400 Invalid Request", "400 Invalid Request", "400 Invalid Request",
                         "403 Access Denied", "404 Not Found", "500 Internal Server Error" };
  char *title  = error_code[code];
  size_t reply_size;

  if( code == CODE_HTTPERROR_302 )
    reply_size = sprintf( static_outbuf, "HTTP/1.0 302 Found\r\nContent-Length: 0\r\nLocation: %s\r\n\r\n", g_redirecturl );
  else
    reply_size = sprintf( static_outbuf, "HTTP/1.0 %s\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: %zd\r\n\r\n<title>%s</title>\n", title, strlen(title)+16-4,title+4);

#ifdef _DEBUG_HTTPERROR
  fprintf( stderr, "DEBUG: invalid request was: %s\n", debug_request );
#endif
  stats_issue_event( EVENT_FAILED, 1, code );
  http_senddata( client_socket, static_outbuf, reply_size);
  return -2;
}

ssize_t http_sendiovecdata( const int64 client_socket, int iovec_entries, struct iovec *iovector ) {
  struct http_data *h = io_getcookie( client_socket );
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

  /* Our answers never are 0 vectors. Return an error. */
  if( !iovec_entries ) {
    HTTPERROR_500;
  }

  /* Prepare space for http header */
  header = malloc( SUCCESS_HTTP_HEADER_LENGTH + SUCCESS_HTTP_HEADER_LENGHT_CONTENT_ENCODING );
  if( !header ) {
    iovec_free( &iovec_entries, &iovector );
    HTTPERROR_500;
  }

  if( h->flag & STRUCT_HTTP_FLAG_GZIP )
    header_size = sprintf( header, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: %zd\r\n\r\n", size );
  else if( h->flag & STRUCT_HTTP_FLAG_BZIP2 )
    header_size = sprintf( header, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: bzip2\r\nContent-Length: %zd\r\n\r\n", size );
  else
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
  io_timeout( client_socket, t );
  io_dontwantread( client_socket );
  io_wantwrite( client_socket );
  return 0;
}

#ifdef WANT_TRACKER_SYNC
static ssize_t http_handle_sync( const int64 client_socket, char *data ) {
  struct http_data* h = io_getcookie( client_socket );
  size_t len;
  int mode = SYNC_OUT, scanon = 1;
  char *c = data;

  if( !accesslist_isblessed( h->ip, OT_PERMISSION_MAY_SYNC ) )
    HTTPERROR_403_IP;

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
      if( add_changeset_to_tracker( (uint8_t*)data, len ) ) HTTPERROR_400_PARAM;
      if( mode == SYNC_OUT ) {
        stats_issue_event( EVENT_SYNC_IN, 1, 0 );
        mode = SYNC_IN;
      }
      break;
    }
  }

  if( mode == SYNC_OUT ) {
    /* Pass this task to the worker thread */
    h->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK;
    stats_issue_event( EVENT_SYNC_OUT_REQUEST, 1, 0 );
    sync_deliver( client_socket );
    io_dontwantread( client_socket );
    return -2;
  }

  /* Simple but proof for now */
  memmove( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH, "OK", 2);
  return 2;
}
#endif

static ssize_t http_handle_stats( const int64 client_socket, char *data, char *d, size_t l ) {
  struct http_data* h = io_getcookie( client_socket );
  char *c = data;
  int mode = TASK_STATS_PEERS, scanon = 1, format = 0;

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
      else if( !byte_diff(data,4,"scrp"))
        mode = TASK_STATS_SCRAPE;
      else if( !byte_diff(data,4,"torr"))
        mode = TASK_STATS_TORRENTS;
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
      else if( !byte_diff(data,4,"herr"))
        mode = TASK_STATS_HTTPERRORS;
      else if( !byte_diff(data,9,"startstop"))
        mode = TASK_STATS_STARTSTOP;
      else if( !byte_diff(data,10,"toraddrem"))
        mode = TASK_STATS_TORADDREM;
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
    tai6464 t;
#ifdef WANT_COMPRESSION_GZIP
    d[l-1] = 0;
    if( strstr( d, "gzip" ) ) {
      h->flag |= STRUCT_HTTP_FLAG_GZIP;
      format |= TASK_FLAG_GZIP;
    }
#else
    /* Touch variable */
    d=d;
#endif
    /* Pass this task to the worker thread */
    h->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK;

    /* Clients waiting for us should not easily timeout */
    taia_uint( &t, 0 ); io_timeout( client_socket, t );
    fullscrape_deliver( client_socket, format );
    io_dontwantread( client_socket );
    return -2;
  }

  /* default format for now */
  if( !( l = return_stats_for_tracker( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH, mode, 0 ) ) ) HTTPERROR_500;
  return l;
}

static ssize_t http_handle_fullscrape( const int64 client_socket, char *d, size_t l ) {
  struct http_data* h = io_getcookie( client_socket );
  int format = 0;
  tai6464 t;

  /* Touch variables */
  d=d;l=l;

#ifdef WANT_COMPRESSION_GZIP
  d[l-1] = 0;
  if( strstr( d, "gzip" ) ) {
    h->flag |= STRUCT_HTTP_FLAG_GZIP;
    format = TASK_FLAG_GZIP;
    stats_issue_event( EVENT_FULLSCRAPE_REQUEST_GZIP, *(int*)h->ip, 0 );
  } else
#endif
    stats_issue_event( EVENT_FULLSCRAPE_REQUEST, *(int*)h->ip, 0 );

#ifdef _DEBUG_HTTPERROR
write( 2, debug_request, l );
#endif

  /* Pass this task to the worker thread */
  h->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK;
  /* Clients waiting for us should not easily timeout */
  taia_uint( &t, 0 ); io_timeout( client_socket, t );
  fullscrape_deliver( client_socket, TASK_FULLSCRAPE | format );
  io_dontwantread( client_socket );
  return -2;
}

static ssize_t http_handle_scrape( const int64 client_socket, char *data ) {
  int scanon = 1, numwant = 0;
  char *c = data;
  size_t l;

  /* This is to hack around stupid clients that send "scrape ?info_hash" */
  if( c[-1] != '?' ) {
    while( ( *c != '?' ) && ( *c != '\n' ) ) ++c;
    if( *c == '\n' ) HTTPERROR_400_PARAM;
    ++c;
  }

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
  if( !( l = return_tcp_scrape_for_torrent( multiscrape_buf, numwant, SUCCESS_HTTP_HEADER_LENGTH + static_outbuf ) ) ) HTTPERROR_500;
  stats_issue_event( EVENT_SCRAPE, 1, l );
  return l;
}

static ssize_t http_handle_announce( const int64 client_socket, char *data ) {
  char       *c = data;
  int         numwant, tmp, scanon;
  ot_peer     peer;
  ot_torrent *torrent;
  ot_hash    *hash = NULL;
  unsigned short port = htons(6881);
  ssize_t     len;

  /* This is to hack around stupid clients that send "announce ?info_hash" */
  if( c[-1] != '?' ) {
    while( ( *c != '?' ) && ( *c != '\n' ) ) ++c;
    if( *c == '\n' ) HTTPERROR_400_PARAM;
    ++c;
  }

  OT_SETIP( &peer, ((struct http_data*)io_getcookie( client_socket ) )->ip );
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
  if( !hash )
    return sprintf( static_outbuf + SUCCESS_HTTP_HEADER_LENGTH, "d14:failure reason81:Your client forgot to send your torrent's info_hash. Please upgrade your client.e" );

  if( OT_FLAG( &peer ) & PEER_FLAG_STOPPED )
    len = remove_peer_from_torrent( hash, &peer, SUCCESS_HTTP_HEADER_LENGTH + static_outbuf, 1 );
  else {
    torrent = add_peer_to_torrent( hash, &peer, 0 );
    if( !torrent || !( len = return_peers_for_torrent( hash, numwant, SUCCESS_HTTP_HEADER_LENGTH + static_outbuf, 1 ) ) ) HTTPERROR_500;
  }
  stats_issue_event( EVENT_ANNOUNCE, 1, len);
  return len;
}

ssize_t http_handle_request( const int64 client_socket, char *data, size_t recv_length ) {
  char       *c, *recv_header=data;
  ssize_t     reply_size = 0, reply_off, len;

#ifdef _DEBUG_HTTPERROR
  if( recv_length >= sizeof( debug_request ) )
    recv_length = sizeof( debug_request) - 1;
  memcpy( debug_request, recv_header, recv_length );
  debug_request[ recv_length ] = 0;
#endif

  /* This one implicitely tests strlen < 5, too -- remember, it is \n terminated */
  if( byte_diff( data, 5, "GET /") ) HTTPERROR_400;

  /* Query string MUST terminate with SP -- we know that theres at least a '\n' where this search terminates */
  for( c = data + 5; *c!=' ' && *c != '\t' && *c != '\n' && *c != '\r'; ++c ) ;
  if( *c != ' ' ) HTTPERROR_400;

  /* Skip leading '/' */
  for( c = data+4; *c == '/'; ++c);

  /* Try to parse the request.
     In reality we abandoned requiring the url to be correct. This now
     only decodes url encoded characters, we check for announces and
     scrapes by looking for "a*" or "sc" */
  len = scan_urlencoded_query( &c, data = c, SCAN_PATH );

  /* If parsing returned an error, leave with not found*/
  if( g_redirecturl && ( len == -2 ) ) HTTPERROR_302;
  if( len <= 0 ) HTTPERROR_404;

  /* This is the hardcore match for announce*/
  if( ( *data == 'a' ) || ( *data == '?' ) )
    reply_size = http_handle_announce( client_socket, c );
  else if( !byte_diff( data, 12, "scrape HTTP/" ) )
    reply_size = http_handle_fullscrape( client_socket, recv_header, recv_length );
  /* This is the hardcore match for scrape */
  else if( !byte_diff( data, 2, "sc" ) )
    reply_size = http_handle_scrape( client_socket, c );
  /* All the rest is matched the standard way */
  else switch( len ) {
#ifdef WANT_TRACKER_SYNC
  case 4: /* sync ? */
    if( byte_diff( data, 4, "sync") ) HTTPERROR_404;
    reply_size = http_handle_sync( client_socket, c );
    break;
#endif
  case 5: /* stats ? */
    if( byte_diff( data, 5, "stats") ) HTTPERROR_404;
    reply_size = http_handle_stats( client_socket, c, recv_header, recv_length );
    break;
  default:
    HTTPERROR_404;
  }

  /* If routines handled sending themselves, just return */
  if( reply_size == -2 ) return 0;
  /* If routine failed, let http error take over */
  if( reply_size == -1 ) HTTPERROR_500;

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

  http_senddata( client_socket, static_outbuf + reply_off, reply_size );
  return reply_size;
}
