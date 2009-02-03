/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Libowfat */
#include "byte.h"
#include "array.h"
#include "iob.h"
#include "ip6.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_http.h"
#include "ot_iovec.h"
#include "scan_urlencoded_query.h"
#include "ot_fullscrape.h"
#include "ot_stats.h"
#include "ot_accesslist.h"

#define OT_MAXMULTISCRAPE_COUNT 64
extern char *g_redirecturl;

enum {
  SUCCESS_HTTP_HEADER_LENGTH = 80,
  SUCCESS_HTTP_HEADER_LENGTH_CONTENT_ENCODING = 32,
  SUCCESS_HTTP_SIZE_OFF = 17 };

static void http_senddata( const int64 sock, struct ot_workstruct *ws ) {
  struct http_data *cookie = io_getcookie( sock );
  ssize_t written_size;

  /* whoever sends data is not interested in its input-array */
  if( cookie && ( cookie->flag & STRUCT_HTTP_FLAG_ARRAY_USED ) ) {
    cookie->flag &= ~STRUCT_HTTP_FLAG_ARRAY_USED;
    array_reset( &cookie->data.request );
  }

  written_size = write( sock, ws->reply, ws->reply_size );
  if( ( written_size < 0 ) || ( written_size == ws->reply_size ) ) {
    free( cookie ); io_close( sock );
  } else {
    char * outbuf;
    tai6464 t;

    if( !cookie ) return;
    if( !( outbuf =  malloc( ws->reply_size - written_size ) ) ) {
      free(cookie); io_close( sock );
      return;
    }

    iob_reset( &cookie->data.batch );
    memcpy( outbuf, ws->reply + written_size, ws->reply_size - written_size );
    iob_addbuf_free( &cookie->data.batch, outbuf, ws->reply_size - written_size );
    cookie->flag |= STRUCT_HTTP_FLAG_IOB_USED;

    /* writeable short data sockets just have a tcp timeout */
    taia_uint( &t, 0 ); io_timeout( sock, t );
    io_dontwantread( sock );
    io_wantwrite( sock );
  }
}

#define HTTPERROR_302            return http_issue_error( sock, ws, CODE_HTTPERROR_302 )
#define HTTPERROR_400            return http_issue_error( sock, ws, CODE_HTTPERROR_400 )
#define HTTPERROR_400_PARAM      return http_issue_error( sock, ws, CODE_HTTPERROR_400_PARAM )
#define HTTPERROR_400_COMPACT    return http_issue_error( sock, ws, CODE_HTTPERROR_400_COMPACT )
#define HTTPERROR_400_DOUBLEHASH return http_issue_error( sock, ws, CODE_HTTPERROR_400_PARAM )
#define HTTPERROR_403_IP         return http_issue_error( sock, ws, CODE_HTTPERROR_403_IP )
#define HTTPERROR_404            return http_issue_error( sock, ws, CODE_HTTPERROR_404 )
#define HTTPERROR_500            return http_issue_error( sock, ws, CODE_HTTPERROR_500 )
ssize_t http_issue_error( const int64 sock, struct ot_workstruct *ws, int code ) {
  char *error_code[] = { "302 Found", "400 Invalid Request", "400 Invalid Request", "400 Invalid Request",
                         "403 Access Denied", "404 Not Found", "500 Internal Server Error" };
  char *title = error_code[code];

  ws->reply = ws->outbuf;
  if( code == CODE_HTTPERROR_302 )
    ws->reply_size = snprintf( ws->reply, G_OUTBUF_SIZE, "HTTP/1.0 302 Found\r\nContent-Length: 0\r\nLocation: %s\r\n\r\n", g_redirecturl );
  else
    ws->reply_size = snprintf( ws->reply, G_OUTBUF_SIZE, "HTTP/1.0 %s\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: %zd\r\n\r\n<title>%s</title>\n", title, strlen(title)+16-4,title+4);

#ifdef _DEBUG_HTTPERROR
  fprintf( stderr, "DEBUG: invalid request was: %s\n", ws->debugbuf );
#endif
  stats_issue_event( EVENT_FAILED, FLAG_TCP, code );
  http_senddata( sock, ws );
  return ws->reply_size = -2;
}

ssize_t http_sendiovecdata( const int64 sock, struct ot_workstruct *ws, int iovec_entries, struct iovec *iovector ) {
  struct http_data *cookie = io_getcookie( sock );
  char *header;
  int i;
  size_t header_size, size = iovec_length( &iovec_entries, &iovector );
  tai6464 t;

  /* No cookie? Bad socket. Leave. */
  if( !cookie ) {
    iovec_free( &iovec_entries, &iovector );
    HTTPERROR_500;
  }

  /* If this socket collected request in a buffer,
     free it now */
  if( cookie->flag & STRUCT_HTTP_FLAG_ARRAY_USED ) {
    cookie->flag &= ~STRUCT_HTTP_FLAG_ARRAY_USED;
    array_reset( &cookie->data.request );
  }

  /* If we came here, wait for the answer is over */
  cookie->flag &= ~STRUCT_HTTP_FLAG_WAITINGFORTASK;

  /* Our answers never are 0 vectors. Return an error. */
  if( !iovec_entries ) {
    HTTPERROR_500;
  }

  /* Prepare space for http header */
  header = malloc( SUCCESS_HTTP_HEADER_LENGTH + SUCCESS_HTTP_HEADER_LENGTH_CONTENT_ENCODING );
  if( !header ) {
    iovec_free( &iovec_entries, &iovector );
    HTTPERROR_500;
  }

  if( cookie->flag & STRUCT_HTTP_FLAG_GZIP )
    header_size = sprintf( header, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: %zd\r\n\r\n", size );
  else if( cookie->flag & STRUCT_HTTP_FLAG_BZIP2 )
    header_size = sprintf( header, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: bzip2\r\nContent-Length: %zd\r\n\r\n", size );
  else
    header_size = sprintf( header, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r\n", size );

  iob_reset( &cookie->data.batch );
  iob_addbuf_free( &cookie->data.batch, header, header_size );

  /* Will move to ot_iovec.c */
  for( i=0; i<iovec_entries; ++i )
    iob_addbuf_munmap( &cookie->data.batch, iovector[i].iov_base, iovector[i].iov_len );
  free( iovector );

  cookie->flag |= STRUCT_HTTP_FLAG_IOB_USED;

  /* writeable sockets timeout after 10 minutes */
  taia_now( &t ); taia_addsec( &t, &t, OT_CLIENT_TIMEOUT_SEND );
  io_timeout( sock, t );
  io_dontwantread( sock );
  io_wantwrite( sock );
  return 0;
}

static ssize_t http_handle_stats( const int64 sock, struct ot_workstruct *ws, char *read_ptr ) {
static const ot_keywords keywords_main[] =
  { { "mode", 1 }, {"format", 2 }, { NULL, -3 } };
static const ot_keywords keywords_mode[] =
  { { "peer", TASK_STATS_PEERS }, { "conn", TASK_STATS_CONNS }, { "scrp", TASK_STATS_SCRAPE }, { "udp4", TASK_STATS_UDP }, { "tcp4", TASK_STATS_TCP },
    { "busy", TASK_STATS_BUSY_NETWORKS }, { "torr", TASK_STATS_TORRENTS }, { "fscr", TASK_STATS_FULLSCRAPE },
    { "s24s", TASK_STATS_SLASH24S }, { "tpbs", TASK_STATS_TPB }, { "herr", TASK_STATS_HTTPERRORS },
    { "top10", TASK_STATS_TOP10 }, { "renew", TASK_STATS_RENEW }, { "syncs", TASK_STATS_SYNCS }, { "version", TASK_STATS_VERSION },
    { "startstop", TASK_STATS_STARTSTOP }, { "toraddrem", TASK_STATS_TORADDREM }, { NULL, -3 } };
static const ot_keywords keywords_format[] =
  { { "bin", TASK_FULLSCRAPE_TPB_BINARY }, { "ben", TASK_FULLSCRAPE }, { "url", TASK_FULLSCRAPE_TPB_URLENCODED },
    { "txt", TASK_FULLSCRAPE_TPB_ASCII }, { NULL, -3 } };

  int mode = TASK_STATS_PEERS, scanon = 1, format = 0;

#ifdef WANT_RESTRICT_STATS
  struct http_data *cookie = io_getcookie( sock );

  if( !cookie || !accesslist_isblessed( cookie->ip, OT_PERMISSION_MAY_STAT ) )
    HTTPERROR_403_IP;
#endif

  while( scanon ) {
    switch( scan_find_keywords( keywords_main, &read_ptr, SCAN_SEARCHPATH_PARAM ) ) {
    case -2: scanon = 0; break;   /* TERMINATOR */
    case -1: HTTPERROR_400_PARAM; /* PARSE ERROR */
    case -3: scan_urlencoded_skipvalue( &read_ptr ); break;
    case  1: /* matched "mode" */
      if( ( mode = scan_find_keywords( keywords_mode, &read_ptr, SCAN_SEARCHPATH_VALUE ) ) <= 0 ) HTTPERROR_400_PARAM;
      break;
    case  2: /* matched "format" */
      if( ( format = scan_find_keywords( keywords_format, &read_ptr, SCAN_SEARCHPATH_VALUE ) ) <= 0 ) HTTPERROR_400_PARAM;
      break;
    }
  }

#ifdef WANT_FULLSCRAPE
  if( mode == TASK_STATS_TPB ) {
    struct http_data* cookie = io_getcookie( sock );
    tai6464 t;
#ifdef WANT_COMPRESSION_GZIP
    ws->request[ws->request_size] = 0;
    if( strstr( read_ptr - 1, "gzip" ) ) {
      cookie->flag |= STRUCT_HTTP_FLAG_GZIP;
      format |= TASK_FLAG_GZIP;
    }
#endif
    /* Pass this task to the worker thread */
    cookie->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK;

    /* Clients waiting for us should not easily timeout */
    taia_uint( &t, 0 ); io_timeout( sock, t );
    fullscrape_deliver( sock, format );
    io_dontwantread( sock );
    return ws->reply_size = -2;
  }
#endif

  /* default format for now */
  if( ( mode & TASK_CLASS_MASK ) == TASK_STATS ) {
    tai6464 t;
    /* Complex stats also include expensive memory debugging tools */
    taia_uint( &t, 0 ); io_timeout( sock, t );
    stats_deliver( sock, mode );
    return ws->reply_size = -2;
  }

  /* Simple stats can be answerred immediately */
  if( !( ws->reply_size = return_stats_for_tracker( ws->reply, mode, 0 ) ) ) HTTPERROR_500;

  return ws->reply_size;
}

#ifdef WANT_FULLSCRAPE
static ssize_t http_handle_fullscrape( const int64 sock, struct ot_workstruct *ws ) {
  struct http_data* cookie = io_getcookie( sock );
  int format = 0;
  tai6464 t;

#ifdef WANT_COMPRESSION_GZIP
  ws->request[ws->request_size-1] = 0;
  if( strstr( ws->request, "gzip" ) ) {
    cookie->flag |= STRUCT_HTTP_FLAG_GZIP;
    format = TASK_FLAG_GZIP;
    stats_issue_event( EVENT_FULLSCRAPE_REQUEST_GZIP, 0, (uintptr_t)cookie->ip );
  } else
#endif
    stats_issue_event( EVENT_FULLSCRAPE_REQUEST, 0, (uintptr_t)cookie->ip );

#ifdef _DEBUG_HTTPERROR
  fprintf( stderr, "%s", ws->debugbuf );
#endif

  /* Pass this task to the worker thread */
  cookie->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK;
  /* Clients waiting for us should not easily timeout */
  taia_uint( &t, 0 ); io_timeout( sock, t );
  fullscrape_deliver( sock, TASK_FULLSCRAPE | format );
  io_dontwantread( sock );
  return ws->reply_size = -2;
}
#endif

static ssize_t http_handle_scrape( const int64 sock, struct ot_workstruct *ws, char *read_ptr ) {
  static const ot_keywords keywords_scrape[] = { { "info_hash", 1 }, { NULL, -3 } };

  ot_hash * multiscrape_buf = (ot_hash*)ws->request;
  int scanon = 1, numwant = 0;

  /* This is to hack around stupid clients that send "scrape ?info_hash" */
  if( read_ptr[-1] != '?' ) {
    while( ( *read_ptr != '?' ) && ( *read_ptr != '\n' ) ) ++read_ptr;
    if( *read_ptr == '\n' ) HTTPERROR_400_PARAM;
    ++read_ptr;
  }

  while( scanon ) {
    switch( scan_find_keywords( keywords_scrape, &read_ptr, SCAN_SEARCHPATH_PARAM ) ) {
    case -2: scanon = 0; break;   /* TERMINATOR */
    default: HTTPERROR_400_PARAM; /* PARSE ERROR */
    case -3: scan_urlencoded_skipvalue( &read_ptr ); break;
    case  1: /* matched "info_hash" */
      /* ignore this, when we have less than 20 bytes */
      if( scan_urlencoded_query( &read_ptr, (char*)(multiscrape_buf + numwant++), SCAN_SEARCHPATH_VALUE ) != (ssize_t)sizeof(ot_hash) )
        HTTPERROR_400_PARAM;
      break;
    }
  }

  /* No info_hash found? Inform user */
  if( !numwant ) HTTPERROR_400_PARAM;
  
  /* Limit number of hashes to process */
  if( numwant > OT_MAXMULTISCRAPE_COUNT )
    numwant = OT_MAXMULTISCRAPE_COUNT;

  /* Enough for http header + whole scrape string */
  if( !( ws->reply_size = return_tcp_scrape_for_torrent( multiscrape_buf, numwant, ws->reply ) ) ) HTTPERROR_500;
  stats_issue_event( EVENT_SCRAPE, FLAG_TCP, ws->reply_size );
  return ws->reply_size;
}

static ot_keywords keywords_announce[] = { { "port", 1 }, { "left", 2 }, { "event", 3 }, { "numwant", 4 }, { "compact", 5 }, { "compact6", 5 }, { "info_hash", 6 },
#ifdef WANT_IP_FROM_QUERY_STRING
{ "ip", 7 },
#endif
{ NULL, -3 } };
static ot_keywords keywords_announce_event[] = { { "completed", 1 }, { "stopped", 2 }, { NULL, -3 } };
static ssize_t http_handle_announce( const int64 sock, struct ot_workstruct *ws, char *read_ptr ) {
  int            numwant, tmp, scanon;
  ot_peer        peer;
  ot_hash       *hash = NULL;
  unsigned short port = htons(6881);
  char          *write_ptr;
  ssize_t        len;
  
  /* This is to hack around stupid clients that send "announce ?info_hash" */
  if( read_ptr[-1] != '?' ) {
    while( ( *read_ptr != '?' ) && ( *read_ptr != '\n' ) ) ++read_ptr;
    if( *read_ptr == '\n' ) HTTPERROR_400_PARAM;
    ++read_ptr;
  }

  OT_SETIP( &peer, ((struct http_data*)io_getcookie( sock ) )->ip );
  OT_SETPORT( &peer, &port );
  OT_PEERFLAG( &peer ) = 0;
  numwant = 50;
  scanon = 1;

  while( scanon ) {
    switch( scan_find_keywords(keywords_announce, &read_ptr, SCAN_SEARCHPATH_PARAM ) ) {
    case -2: scanon = 0; break;   /* TERMINATOR */
    case -1: HTTPERROR_400_PARAM; /* PARSE ERROR */
    case -3: scan_urlencoded_skipvalue( &read_ptr ); break;
    case 1: /* matched "port" */
      len = scan_urlencoded_query( &read_ptr, write_ptr = read_ptr, SCAN_SEARCHPATH_VALUE );
      if( ( len <= 0 ) || scan_fixed_int( write_ptr, len, &tmp ) || ( tmp > 0xffff ) ) HTTPERROR_400_PARAM;
      port = htons( tmp ); OT_SETPORT( &peer, &port );
      break;
    case 2: /* matched "left" */
      if( ( len = scan_urlencoded_query( &read_ptr, write_ptr = read_ptr, SCAN_SEARCHPATH_VALUE ) ) <= 0 ) HTTPERROR_400_PARAM;
      if( scan_fixed_int( write_ptr, len, &tmp ) ) tmp = 0;
      if( !tmp ) OT_PEERFLAG( &peer ) |= PEER_FLAG_SEEDING;
      break;
    case 3: /* matched "event" */
      switch( scan_find_keywords( keywords_announce_event, &read_ptr, SCAN_SEARCHPATH_VALUE ) ) {
        case -1: HTTPERROR_400_PARAM;
        case  1: /* matched "completed" */
          OT_PEERFLAG( &peer ) |= PEER_FLAG_COMPLETED;
          break;
        case  2: /* matched "stopped" */
          OT_PEERFLAG( &peer ) |= PEER_FLAG_STOPPED;
          break;
        default:
          break;
      }
      break;
    case 4: /* matched "numwant" */
      len = scan_urlencoded_query( &read_ptr, write_ptr = read_ptr, SCAN_SEARCHPATH_VALUE );
      if( ( len <= 0 ) || scan_fixed_int( write_ptr, len, &numwant ) ) HTTPERROR_400_PARAM;
      if( numwant < 0 ) numwant = 50;
      if( numwant > 200 ) numwant = 200;
      break;
    case 5: /* matched "compact" */
      len = scan_urlencoded_query( &read_ptr, write_ptr = read_ptr, SCAN_SEARCHPATH_VALUE );
      if( ( len <= 0 ) || scan_fixed_int( write_ptr, len, &tmp ) ) HTTPERROR_400_PARAM;
      if( !tmp ) HTTPERROR_400_COMPACT;
      break;
    case 6: /* matched "info_hash" */
      if( hash ) HTTPERROR_400_DOUBLEHASH;
      /* ignore this, when we have less than 20 bytes */
      if( scan_urlencoded_query( &read_ptr, write_ptr = read_ptr, SCAN_SEARCHPATH_VALUE ) != 20 ) HTTPERROR_400_PARAM;
        hash = (ot_hash*)write_ptr;
      break;
#ifdef WANT_IP_FROM_QUERY_STRING
    case  7: /* matched "ip" */
      {
        char *tmp_buf1 = ws->reply, *tmp_buf2 = ws->reply+16;
        len = scan_urlencoded_query( &read_ptr, tmp_buf2, SCAN_SEARCHPATH_VALUE );
        tmp_buf2[len] = 0;
        if( ( len <= 0 ) || scan_ip6( tmp_buf2, tmp_buf1 ) ) HTTPERROR_400_PARAM;
        OT_SETIP( &peer, tmp_buf1 );
      }
      break;
#endif
    }
  }

  /* Scanned whole query string */
  if( !hash )
    return ws->reply_size = sprintf( ws->reply, "d14:failure reason80:Your client forgot to send your torrent's info_hash. Please upgrade your client.e" );

  if( OT_PEERFLAG( &peer ) & PEER_FLAG_STOPPED )
    ws->reply_size = remove_peer_from_torrent( *hash, &peer, ws->reply, FLAG_TCP );
  else
    ws->reply_size = add_peer_to_torrent_and_return_peers( *hash, &peer, FLAG_TCP, numwant, ws->reply );

  if( !ws->reply_size ) HTTPERROR_500;

  stats_issue_event( EVENT_ANNOUNCE, FLAG_TCP, ws->reply_size);
  return ws->reply_size;
}

ssize_t http_handle_request( const int64 sock, struct ot_workstruct *ws ) {
  ssize_t reply_off, len;
  char   *read_ptr = ws->request, *write_ptr;

#ifdef _DEBUG_HTTPERROR
  reply_off = ws->request_size;
  if( ws->request_size >= G_DEBUGBUF_SIZE )
    reply_off = G_DEBUGBUF_SIZE - 1;
  memcpy( ws->debugbuf, ws->request, reply_off );
  ws->debugbuf[ reply_off ] = 0;
#endif

  /* Tell subroutines where to put reply data */
  ws->reply = ws->outbuf + SUCCESS_HTTP_HEADER_LENGTH;

  /* This one implicitely tests strlen < 5, too -- remember, it is \n terminated */
  if( memcmp( read_ptr, "GET /", 5) ) HTTPERROR_400;

  /* Skip leading '/' */
  for( read_ptr+=4; *read_ptr == '/'; ++read_ptr);

  /* Try to parse the request.
     In reality we abandoned requiring the url to be correct. This now
     only decodes url encoded characters, we check for announces and
     scrapes by looking for "a*" or "sc" */
  len = scan_urlencoded_query( &read_ptr, write_ptr = read_ptr, SCAN_PATH );

  /* If parsing returned an error, leave with not found */
  if( g_redirecturl && ( len == -2 ) ) HTTPERROR_302;
  if( len <= 0 ) HTTPERROR_404;

  /* This is the hardcore match for announce*/
  if( ( *write_ptr == 'a' ) || ( *write_ptr == '?' ) )
    http_handle_announce( sock, ws, read_ptr );
#ifdef WANT_FULLSCRAPE
  else if( !memcmp( write_ptr, "scrape HTTP/", 12 ) )
    http_handle_fullscrape( sock, ws );
#endif
  /* This is the hardcore match for scrape */
  else if( !memcmp( write_ptr, "sc", 2 ) )
    http_handle_scrape( sock, ws, read_ptr );
  /* All the rest is matched the standard way */
  else if( !memcmp( write_ptr, "stats", 5) )
    http_handle_stats( sock, ws, read_ptr );
  else
    HTTPERROR_404;

  /* If routines handled sending themselves, just return */
  if( ws->reply_size == -2 ) return 0;
  /* If routine failed, let http error take over */
  if( ws->reply_size == -1 ) HTTPERROR_500;

  /* This one is rather ugly, so I take you step by step through it.

     1. In order to avoid having two buffers, one for header and one for content, we allow all above functions from trackerlogic to
     write to a fixed location, leaving SUCCESS_HTTP_HEADER_LENGTH bytes in our work buffer, which is enough for the static string
     plus dynamic space needed to expand our Content-Length value. We reserve SUCCESS_HTTP_SIZE_OFF for its expansion and calculate
     the space NOT needed to expand in reply_off
  */
  reply_off = SUCCESS_HTTP_SIZE_OFF - snprintf( ws->outbuf, 0, "%zd", ws->reply_size );
  ws->reply = ws->outbuf + reply_off;
  
  /* 2. Now we sprintf our header so that sprintf writes its terminating '\0' exactly one byte before content starts. Complete
     packet size is increased by size of header plus one byte '\n', we  will copy over '\0' in next step */
  ws->reply_size += 1 + sprintf( ws->reply, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r", ws->reply_size );

  /* 3. Finally we join both blocks neatly */
  ws->outbuf[ SUCCESS_HTTP_HEADER_LENGTH - 1 ] = '\n';
  
  http_senddata( sock, ws );
  return ws->reply_size;
}

const char *g_version_http_c = "$Source$: $Revision$\n";
