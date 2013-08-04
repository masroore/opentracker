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
#include <pthread.h>

/* Libowfat */
#include "byte.h"
#include "array.h"
#include "iob.h"
#include "ip6.h"
#include "scan.h"
#include "case.h"

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

char   *g_stats_path;
ssize_t g_stats_path_len;

enum {
  SUCCESS_HTTP_HEADER_LENGTH = 80,
  SUCCESS_HTTP_HEADER_LENGTH_CONTENT_ENCODING = 32,
  SUCCESS_HTTP_SIZE_OFF = 17 };

static void http_senddata( const int64 sock, struct ot_workstruct *ws ) {
  struct http_data *cookie = io_getcookie( sock );
  ssize_t written_size;

  if( !cookie ) { io_close(sock); return; }

  /* whoever sends data is not interested in its input-array */
  if( ws->keep_alive && ws->header_size != ws->request_size ) {
    size_t rest = ws->request_size - ws->header_size;
    if( array_start(&cookie->request) ) {
      memmove( array_start(&cookie->request), ws->request + ws->header_size, rest );
      array_truncate( &cookie->request, 1, rest );
    } else
      array_catb(&cookie->request, ws->request + ws->header_size, rest );    
  } else
    array_reset( &cookie->request );

  written_size = write( sock, ws->reply, ws->reply_size );
  if( ( written_size < 0 ) || ( ( written_size == ws->reply_size ) && !ws->keep_alive ) ) {
    array_reset( &cookie->request );
    free( cookie ); io_close( sock ); return;
  }

  if( written_size < ws->reply_size ) {
    char * outbuf;
    tai6464 t;

    if( !( outbuf = malloc( ws->reply_size - written_size ) ) ) {
      array_reset( &cookie->request );
      free(cookie); io_close( sock );
      return;
    }

    memcpy( outbuf, ws->reply + written_size, ws->reply_size - written_size );
    iob_addbuf_free( &cookie->batch, outbuf, ws->reply_size - written_size );

    /* writeable short data sockets just have a tcp timeout */
    if( !ws->keep_alive ) {
      taia_uint( &t, 0 ); io_timeout( sock, t );
      io_dontwantread( sock );
    }
    io_wantwrite( sock );
  }
}

#define HTTPERROR_302            return http_issue_error( sock, ws, CODE_HTTPERROR_302 )
#define HTTPERROR_400            return http_issue_error( sock, ws, CODE_HTTPERROR_400 )
#define HTTPERROR_400_PARAM      return http_issue_error( sock, ws, CODE_HTTPERROR_400_PARAM )
#define HTTPERROR_400_COMPACT    return http_issue_error( sock, ws, CODE_HTTPERROR_400_COMPACT )
#define HTTPERROR_400_DOUBLEHASH return http_issue_error( sock, ws, CODE_HTTPERROR_400_PARAM )
#define HTTPERROR_402_NOTMODEST  return http_issue_error( sock, ws, CODE_HTTPERROR_402_NOTMODEST )
#define HTTPERROR_403_IP         return http_issue_error( sock, ws, CODE_HTTPERROR_403_IP )
#define HTTPERROR_404            return http_issue_error( sock, ws, CODE_HTTPERROR_404 )
#define HTTPERROR_500            return http_issue_error( sock, ws, CODE_HTTPERROR_500 )
ssize_t http_issue_error( const int64 sock, struct ot_workstruct *ws, int code ) {
  char *error_code[] = { "302 Found", "400 Invalid Request", "400 Invalid Request", "400 Invalid Request", "402 Payment Required",
                         "403 Not Modest", "403 Access Denied", "404 Not Found", "500 Internal Server Error" };
  char *title = error_code[code];

  ws->reply = ws->outbuf;
  if( code == CODE_HTTPERROR_302 )
    ws->reply_size = snprintf( ws->reply, G_OUTBUF_SIZE, "HTTP/1.0 302 Found\r\nContent-Length: 0\r\nLocation: %s\r\n\r\n", g_redirecturl );
  else
    ws->reply_size = snprintf( ws->reply, G_OUTBUF_SIZE, "HTTP/1.0 %s\r\nContent-Type: text/html\r\nContent-Length: %zd\r\n\r\n<title>%s</title>\n", title, strlen(title)+16-4,title+4);

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

  /* If this socket collected request in a buffer, free it now */
  array_reset( &cookie->request );

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

  iob_reset( &cookie->batch );
  iob_addbuf_free( &cookie->batch, header, header_size );

  /* Will move to ot_iovec.c */
  for( i=0; i<iovec_entries; ++i )
    iob_addbuf_munmap( &cookie->batch, iovector[i].iov_base, iovector[i].iov_len );
  free( iovector );

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
    { "s24s", TASK_STATS_SLASH24S }, { "tpbs", TASK_STATS_TPB }, { "herr", TASK_STATS_HTTPERRORS }, { "completed", TASK_STATS_COMPLETED },
    { "top100", TASK_STATS_TOP100 }, { "top10", TASK_STATS_TOP10 }, { "renew", TASK_STATS_RENEW }, { "syncs", TASK_STATS_SYNCS }, { "version", TASK_STATS_VERSION },
    { "everything", TASK_STATS_EVERYTHING }, { "statedump", TASK_FULLSCRAPE_TRACKERSTATE }, { "fulllog", TASK_STATS_FULLLOG },
    { "woodpeckers", TASK_STATS_WOODPECKERS},
#ifdef WANT_LOG_NUMWANT
    { "numwants", TASK_STATS_NUMWANTS},
#endif
    { NULL, -3 } };
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
  if( mode == TASK_FULLSCRAPE_TRACKERSTATE ) {
    format = mode; mode = TASK_STATS_TPB;
  }

  if( mode == TASK_STATS_TPB ) {
    struct http_data* cookie = io_getcookie( sock );
    tai6464 t;
#ifdef WANT_COMPRESSION_GZIP
    ws->request[ws->request_size] = 0;
#ifdef WANT_COMPRESSION_GZIP_ALWAYS
    if( strstr( read_ptr - 1, "gzip" ) ) {
#endif
      cookie->flag |= STRUCT_HTTP_FLAG_GZIP;
      format |= TASK_FLAG_GZIP;
#ifdef WANT_COMPRESSION_GZIP_ALWAYS
    }
#endif
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
  return ws->reply_size = return_stats_for_tracker( ws->reply, mode, 0 );
}

#ifdef WANT_MODEST_FULLSCRAPES
static pthread_mutex_t g_modest_fullscrape_mutex = PTHREAD_MUTEX_INITIALIZER; 
static ot_vector g_modest_fullscrape_timeouts;
typedef struct { ot_ip6 ip; ot_time last_fullscrape; } ot_scrape_log;
#endif

#ifdef WANT_FULLSCRAPE
static ssize_t http_handle_fullscrape( const int64 sock, struct ot_workstruct *ws ) {
  struct http_data* cookie = io_getcookie( sock );
  int format = 0;
  tai6464 t;

#ifdef WANT_MODEST_FULLSCRAPES
  {
    ot_scrape_log this_peer, *new_peer;
    int exactmatch;
    memcpy( this_peer.ip, cookie->ip, sizeof(ot_ip6));
    this_peer.last_fullscrape = g_now_seconds;
    pthread_mutex_lock(&g_modest_fullscrape_mutex);
    new_peer = vector_find_or_insert( &g_modest_fullscrape_timeouts, &this_peer, sizeof(ot_scrape_log), sizeof(ot_ip6), &exactmatch );
    if( !new_peer ) {
      pthread_mutex_unlock(&g_modest_fullscrape_mutex);
      HTTPERROR_500;
    }
    if( exactmatch && ( this_peer.last_fullscrape - new_peer->last_fullscrape ) < OT_MODEST_PEER_TIMEOUT ) {
      pthread_mutex_unlock(&g_modest_fullscrape_mutex);
      HTTPERROR_402_NOTMODEST;
    }
    memcpy( new_peer, &this_peer, sizeof(ot_scrape_log));
    pthread_mutex_unlock(&g_modest_fullscrape_mutex);
  }
#endif

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
  ws->reply_size = return_tcp_scrape_for_torrent( multiscrape_buf, numwant, ws->reply );
  stats_issue_event( EVENT_SCRAPE, FLAG_TCP, ws->reply_size );
  return ws->reply_size;
}

#ifdef WANT_LOG_NUMWANT
  unsigned long long numwants[201];
#endif

#if defined( WANT_KEEPALIVE ) || defined( WANT_IP_FROM_PROXY )
static char* http_header( char *data, size_t byte_count, char *header ) {
  size_t i;
  long sl = strlen( header );
  for( i = 0; i + sl + 2 < byte_count; ++i ) {
    if( data[i] != '\n' || data[ i + sl + 1] != ':' ) continue;
    if( !case_equalb( data + i + 1, sl, header ) ) continue;
    data += i + sl + 2;
    while( *data == ' ' || *data == '\t' ) ++data;
    return data;
  }
  return 0;
}
#endif

static ot_keywords keywords_announce[] = { { "port", 1 }, { "left", 2 }, { "event", 3 }, { "numwant", 4 }, { "compact", 5 }, { "compact6", 5 }, { "info_hash", 6 },
#ifdef WANT_IP_FROM_QUERY_STRING
{ "ip", 7 },
#endif
#ifdef WANT_FULLLOG_NETWORKS
{ "lognet", 8 },
#endif
{ "peer_id", 9 },
{ NULL, -3 } };
static ot_keywords keywords_announce_event[] = { { "completed", 1 }, { "stopped", 2 }, { NULL, -3 } };
static ssize_t http_handle_announce( const int64 sock, struct ot_workstruct *ws, char *read_ptr ) {
  int               numwant, tmp, scanon;
  unsigned short    port = 0;
  char             *write_ptr;
  ssize_t           len;
  struct http_data *cookie = io_getcookie( sock );

  /* This is to hack around stupid clients that send "announce ?info_hash" */
  if( read_ptr[-1] != '?' ) {
    while( ( *read_ptr != '?' ) && ( *read_ptr != '\n' ) ) ++read_ptr;
    if( *read_ptr == '\n' ) HTTPERROR_400_PARAM;
    ++read_ptr;
  }

#ifdef WANT_IP_FROM_PROXY
  if( accesslist_isblessed( cookie->ip, OT_PERMISSION_MAY_PROXY ) ) {
    ot_ip6 proxied_ip;
    char *fwd = http_header( ws->request, ws->header_size, "x-forwarded-for" );
    if( fwd && scan_ip6( fwd, proxied_ip ) )
      OT_SETIP( &ws->peer, proxied_ip );
    else
      OT_SETIP( &ws->peer, cookie->ip );
  } else
#endif
  OT_SETIP( &ws->peer, cookie->ip );

  ws->peer_id = NULL;
  ws->hash = NULL;

  OT_SETPORT( &ws->peer, &port );
  OT_PEERFLAG( &ws->peer ) = 0;
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
      port = htons( tmp ); OT_SETPORT( &ws->peer, &port );
      break;
    case 2: /* matched "left" */
      if( ( len = scan_urlencoded_query( &read_ptr, write_ptr = read_ptr, SCAN_SEARCHPATH_VALUE ) ) <= 0 ) HTTPERROR_400_PARAM;
      if( scan_fixed_int( write_ptr, len, &tmp ) ) tmp = 0;
      if( !tmp ) OT_PEERFLAG( &ws->peer ) |= PEER_FLAG_SEEDING;
      break;
    case 3: /* matched "event" */
      switch( scan_find_keywords( keywords_announce_event, &read_ptr, SCAN_SEARCHPATH_VALUE ) ) {
        case -1: HTTPERROR_400_PARAM;
        case  1: /* matched "completed" */
          OT_PEERFLAG( &ws->peer ) |= PEER_FLAG_COMPLETED;
          break;
        case  2: /* matched "stopped" */
          OT_PEERFLAG( &ws->peer ) |= PEER_FLAG_STOPPED;
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
      if( ws->hash ) HTTPERROR_400_DOUBLEHASH;
      /* ignore this, when we have less than 20 bytes */
      if( scan_urlencoded_query( &read_ptr, write_ptr = read_ptr, SCAN_SEARCHPATH_VALUE ) != 20 ) HTTPERROR_400_PARAM;
        ws->hash = (ot_hash*)write_ptr;
      break;
#ifdef WANT_IP_FROM_QUERY_STRING
    case  7: /* matched "ip" */
      {
        char *tmp_buf1 = ws->reply, *tmp_buf2 = ws->reply+16;
        len = scan_urlencoded_query( &read_ptr, tmp_buf2, SCAN_SEARCHPATH_VALUE );
        tmp_buf2[len] = 0;
        if( ( len <= 0 ) || !scan_ip6( tmp_buf2, tmp_buf1 ) ) HTTPERROR_400_PARAM;
        OT_SETIP( &ws->peer, tmp_buf1 );
      }
      break;
#endif
#ifdef WANT_FULLLOG_NETWORKS
      case 8: /* matched "lognet" */
      {
        //if( accesslist_isblessed( cookie->ip, OT_PERMISSION_MAY_STAT ) ) {
          char *tmp_buf = ws->reply;
          ot_net net;
          signed short parsed, bits;

          len = scan_urlencoded_query( &read_ptr, tmp_buf, SCAN_SEARCHPATH_VALUE );
          tmp_buf[len] = 0;
          if( len <= 0 ) HTTPERROR_400_PARAM;
          if( *tmp_buf == '-' ) {
            loglist_reset( );
            return ws->reply_size = sprintf( ws->reply, "Successfully removed.\n" );
          }
          parsed = scan_ip6( tmp_buf, net.address );
          if( !parsed ) HTTPERROR_400_PARAM;
          if( tmp_buf[parsed++] != '/' )
            bits = 128;
          else {
            parsed = scan_short( tmp_buf + parsed, &bits );
            if( !parsed ) HTTPERROR_400_PARAM; 
            if( ip6_isv4mapped( net.address ) )
              bits += 96;
          }
          net.bits = bits;
          loglist_add_network( &net );
          return ws->reply_size = sprintf( ws->reply, "Successfully added.\n" );
        //}
      }
#endif
        break;
      case 9: /* matched "peer_id" */
        /* ignore this, when we have less than 20 bytes */
        if( scan_urlencoded_query( &read_ptr, write_ptr = read_ptr, SCAN_SEARCHPATH_VALUE ) != 20 ) HTTPERROR_400_PARAM;
        ws->peer_id = write_ptr;
        break;
    }
  }

#ifdef WANT_LOG_NUMWANT
  numwants[numwant]++;
#endif

  /* XXX DEBUG */
  stats_issue_event( EVENT_ACCEPT, FLAG_TCP, (uintptr_t)ws->reply );

  /* Scanned whole query string */
  if( !ws->hash )
    return ws->reply_size = sprintf( ws->reply, "d14:failure reason80:Your client forgot to send your torrent's info_hash. Please upgrade your client.e" );

  if( OT_PEERFLAG( &ws->peer ) & PEER_FLAG_STOPPED )
    ws->reply_size = remove_peer_from_torrent( FLAG_TCP, ws );
  else
    ws->reply_size = add_peer_to_torrent_and_return_peers( FLAG_TCP, ws, numwant );

  stats_issue_event( EVENT_ANNOUNCE, FLAG_TCP, ws->reply_size);
  return ws->reply_size;
}

ssize_t http_handle_request( const int64 sock, struct ot_workstruct *ws ) {
  ssize_t reply_off, len;
  char   *read_ptr = ws->request, *write_ptr;

#ifdef WANT_FULLLOG_NETWORKS
  struct http_data *cookie = io_getcookie( sock );
  if( loglist_check_address( cookie->ip ) ) {
    ot_log *log = malloc( sizeof( ot_log ) );
    if( log ) {
      log->size = ws->request_size;
      log->data = malloc( ws->request_size );
      log->next = 0;
      log->time = g_now_seconds;
      memcpy( log->ip, cookie->ip, sizeof(ot_ip6));
      if( log->data ) {
        memcpy( log->data, ws->request, ws->request_size );
        if( !g_logchain_first )
          g_logchain_first = g_logchain_last = log;
        else {
          g_logchain_last->next = log;
          g_logchain_last = log;  
        }        
      } else
        free( log );
    }
  }
#endif

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
  else if( len == g_stats_path_len && !memcmp( write_ptr, g_stats_path, len ) )
    http_handle_stats( sock, ws, read_ptr );
  else
    HTTPERROR_404;

  /* Find out if the client wants to keep this connection alive */
  ws->keep_alive = 0;
#ifdef WANT_KEEPALIVE
  read_ptr=http_header( ws->request, ws->header_size, "connection");
  if( read_ptr && ( *read_ptr == 'K' || *read_ptr == 'k' ) ) ws->keep_alive = 1;
#endif

  /* If routines handled sending themselves, just return */
  if( ws->reply_size == -2 ) return 0;
  /* If routine failed, let http error take over */
  if( ws->reply_size <= 0 ) HTTPERROR_500;

  /* This one is rather ugly, so I take you step by step through it.

     1. In order to avoid having two buffers, one for header and one for content, we allow all above functions from trackerlogic to
     write to a fixed location, leaving SUCCESS_HTTP_HEADER_LENGTH bytes in our work buffer, which is enough for the static string
     plus dynamic space needed to expand our Content-Length value. We reserve SUCCESS_HTTP_SIZE_OFF for its expansion and calculate
     the space NOT needed to expand in reply_off
  */
  reply_off = SUCCESS_HTTP_SIZE_OFF - snprintf( ws->outbuf, 0, "%zd", ws->reply_size );
  ws->reply = ws->outbuf + reply_off;

  /* 2. Now we sprintf our header so that sprintf writes its terminating '\0' exactly one byte before content starts. Complete
     packet size is increased by size of header plus one byte '\n', we will copy over '\0' in next step */
  ws->reply_size += 1 + sprintf( ws->reply, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r", ws->reply_size );

  /* 3. Finally we join both blocks neatly */
  ws->outbuf[ SUCCESS_HTTP_HEADER_LENGTH - 1 ] = '\n';

  http_senddata( sock, ws );
  return ws->reply_size;
}

const char *g_version_http_c = "$Source$: $Revision$\n";
