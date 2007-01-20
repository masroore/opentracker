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

unsigned int const OT_CLIENT_TIMEOUT = 30;
unsigned int const OT_CLIENT_TIMEOUT_CHECKINTERVAL = 5;

static unsigned int ot_overall_connections = 0;
static time_t ot_start_time;
static const size_t SUCCESS_HTTP_HEADER_LENGTH = 80;
static const size_t SUCCESS_HTTP_SIZE_OFF = 17;
/* To always have space for error messages ;) */
static char static_scratch[8192];

#ifdef _DEBUG_FDS
static char fd_debug_space[0x10000];
#endif

static void carp(const char* routine) {
  buffer_puts(buffer_2,routine);
  buffer_puts(buffer_2,": ");
  buffer_puterror(buffer_2);
  buffer_putnlflush(buffer_2);
}

static void panic(const char* routine) {
  carp(routine);
  exit(111);
}

struct http_data {
  union {
    array    r;
    io_batch batch;
  };
  unsigned char ip[4];
};

int header_complete(struct http_data* r) {
  int l = array_bytes(&r->r), i;
  const char* c = array_start(&r->r);

  for (i=0; i+1<l; ++i) {
    if (c[i]=='\n' && c[i+1]=='\n') return i+2;
    if (i+3<l && c[i]=='\r' && c[i+1]=='\n' && c[i+2]=='\r' && c[i+3]=='\n') return i+4;
  }
  return 0;
}

void sendmallocdata( int64 s, struct http_data *h, char * buffer, size_t size ) {
  tai6464 t;
  char *header;
  size_t header_size;

  if( !h ) { free( buffer); return; }
  array_reset(&h->r);

  header = malloc( SUCCESS_HTTP_HEADER_LENGTH );
  if( !header ) { free( buffer ); return; }

  header_size = sprintf( header, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r\n", size );

  iob_reset( &h->batch );
  iob_addbuf_free( &h->batch, header, header_size );
  iob_addbuf_free( &h->batch, buffer, size );

  // writeable sockets just have a tcp timeout
  taia_uint(&t,0); io_timeout( s, t );
  io_dontwantread( s );
  io_wantwrite( s );
}

/* whoever sends data is not interested in its input-array */
void senddata(int64 s, struct http_data* h, char *buffer, size_t size ) {
  size_t written_size;

  if( h ) array_reset(&h->r);
  written_size = write( s, buffer, size );
  if( ( written_size < 0 ) || ( written_size == size ) ) {
#ifdef _DEBUG_FDS
  if( !fd_debug_space[s] ) fprintf( stderr, "close on non-open fd\n" );
  fd_debug_space[s] = 0;
#endif
    free(h); io_close( s );
  } else {
    char * outbuf = malloc( size - written_size );
    tai6464 t;

    if( !outbuf ) {
#ifdef _DEBUG_FDS
      if( !fd_debug_space[s] ) fprintf( stderr, "close on non-open fd\n" );
      fd_debug_space[s] = 0;
#endif
      free(h); io_close( s );
      return;
    }

    iob_reset( &h->batch );
    memmove( outbuf, buffer + written_size, size - written_size );
    iob_addbuf_free( &h->batch, outbuf, size - written_size );

    // writeable sockets just have a tcp timeout
    taia_uint(&t,0); io_timeout( s, t );
    io_dontwantread( s );
    io_wantwrite( s );
  }
}

void httperror(int64 s,struct http_data* h,const char* title,const char* message) {
  size_t reply_size = sprintf( static_scratch, "HTTP/1.0 %s\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: %zd\r\n\r\n<title>%s</title>\n",
                        title, strlen(message)+strlen(title)+16-4,title+4);
  senddata(s,h,static_scratch,reply_size);
}

const char* http_header(struct http_data* r,const char* h) {
  int i, l = array_bytes(&r->r);
  int sl = strlen(h);
  const char* c = array_start(&r->r);

  for (i=0; i+sl+2<l; ++i) {
    if (c[i]=='\n' && case_equalb(c+i+1,sl,h) && c[i+sl+1]==':') {
      c+=i+sl+1;
      if (*c==' ' || *c=='\t') ++c;
      return c;
    }
    return 0;
  }
  return 0;
}

void httpresponse(int64 s,struct http_data* h)
{
  char       *c, *data;
  ot_peer     peer;
  ot_torrent *torrent;
  ot_hash    *hash = NULL;
  int         numwant, tmp, scanon, mode;
  unsigned short port = htons(6881);
  size_t      reply_size = 0;

  array_cat0(&h->r);
  c = array_start(&h->r);

  if (byte_diff(c,4,"GET ")) {
e400:
    return httperror(s,h,"400 Invalid Request","This server only understands GET.");
  }

  c+=4;
  for (data=c; *data!=' '&&*data!='\t'&&*data!='\n'&&*data!='\r'; ++data) ;

  if (*data!=' ') goto e400;
  *data=0;
  if (c[0]!='/') goto e404;
  while (*c=='/') ++c;

  switch( scan_urlencoded_query( &c, data = c, SCAN_PATH ) ) {
  case 5: /* scrape ? */
    if (byte_diff(data,5,"stats"))
      goto e404;
    scanon = 1;
    mode = STATS_MRTG;

    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: /* terminator */
        scanon = 0;
        break;
      case -1: /* error */
        goto e404;
      case 4:
        if(byte_diff(data,4,"mode")) {
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          continue;
        }
        size_t len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
        if( len <= 0 ) goto e400_param;
        if( !byte_diff(data,4,"mrtg"))
          mode = STATS_MRTG;
        else if( !byte_diff(data,4,"top5"))
          mode = STATS_TOP5;
        else
          goto e400_param;
      default:
        scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
        break;
      }
    }

    /* Enough for http header + whole scrape string */
    if( ( reply_size = return_stats_for_tracker( SUCCESS_HTTP_HEADER_LENGTH + static_scratch, mode ) ) <= 0 )	
      goto e500;
    break;
  case 6: /* scrape ? */
    if (byte_diff(data,6,"scrape"))
      goto e404;
    scanon = 1;

    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: /* terminator */
        scanon = 0;
        break;
      case -1: /* error */
        goto e404;
      case 9:
        if(byte_diff(data,9,"info_hash")) {
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          continue;
        }
        /* ignore this, when we have less than 20 bytes */
        if( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) != 20 ) {
e400_param:
          return httperror(s,h,"400 Invalid Request","Invalid parameter");
        }
        hash = (ot_hash*)data; /* Fall through intended */
        break;
      default:
        scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
        break;
      }
    }

    /* Scanned whole query string, no hash means full scrape... you might want to limit that */
    if( !hash ) {
      char * reply;

      reply_size = return_fullscrape_for_tracker( &reply );
      if( reply_size )
        return sendmallocdata( s, h, reply, reply_size );

      goto e500;
    } else {
      /* Enough for http header + whole scrape string */
      if( ( reply_size = return_scrape_for_torrent( hash, SUCCESS_HTTP_HEADER_LENGTH + static_scratch ) ) <= 0 )
        goto e500;
    }
    break;
  case 8: 
    if( byte_diff(data,8,"announce"))
      goto e404;

    OT_SETIP( &peer, h->ip);
    OT_SETPORT( &peer, &port );
    OT_FLAG( &peer ) = 0;
    numwant = 50;
    scanon = 1;

    while( scanon ) {
      switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
      case -2: /* terminator */
        scanon = 0;
        break;
      case -1: /* error */
        goto e404;
#ifdef WANT_IP_FROM_QUERY_STRING
      case 2:
        if(!byte_diff(data,2,"ip")) {
          size_t len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          unsigned char ip[4];
          if( ( len <= 0 ) || scan_fixed_ip( data, len, ip ) ) goto e400_param;
          OT_SETIP ( &peer, ip );
       } else
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
       break;
#endif
      case 4:
        if(!byte_diff(data,4,"port")) {
          size_t len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          if( ( len <= 0 ) || scan_fixed_int( data, len, &tmp ) || ( tmp > 0xffff ) ) goto e400_param;
          port = htons( tmp ); OT_SETPORT ( &peer, &port );
        } else if(!byte_diff(data,4,"left")) {
          size_t len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          if( ( len <= 0 ) || scan_fixed_int( data, len, &tmp ) ) goto e400_param;
          if( !tmp ) OT_FLAG( &peer ) |= PEER_FLAG_SEEDING;
        } else
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
        break;
      case 5:
        if(byte_diff(data,5,"event"))
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
        else switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) ) {
        case -1:
          goto e400_param;
        case 7:
          if(!byte_diff(data,7,"stopped")) OT_FLAG( &peer ) |= PEER_FLAG_STOPPED;
          break;
        case 9:
          if(!byte_diff(data,9,"complete")) OT_FLAG( &peer ) |= PEER_FLAG_COMPLETED;
        default: /* Fall through intended */
          break;
        }
        break;
      case 7:
        if(!byte_diff(data,7,"numwant")) {
          size_t len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          if( ( len <= 0 ) || scan_fixed_int( data, len, &numwant ) ) goto e400_param;
          if( numwant > 200 ) numwant = 200;
        } else if(!byte_diff(data,7,"compact")) {
          size_t len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
          if( ( len <= 0 ) || scan_fixed_int( data, len, &tmp ) ) goto e400_param;
          if( !tmp )
            return httperror(s,h,"400 Invalid Request","This server only delivers compact results.");
        } else
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
        break;
      case 9:
        if(byte_diff(data,9,"info_hash")) {
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          continue;
        }
        /* ignore this, when we have less than 20 bytes */
        if( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) != 20 )
          goto e400;
        hash = (ot_hash*)data;
        break;
      default:
        scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
        break;
      }
    }

    /* Scanned whole query string */
    if( !hash ) goto e400;

    if( OT_FLAG( &peer ) & PEER_FLAG_STOPPED ) {
      remove_peer_from_torrent( hash, &peer );
      memmove( static_scratch + SUCCESS_HTTP_HEADER_LENGTH, "d8:completei0e10:incompletei0e8:intervali1800e5:peers0:e", reply_size = 56 );
    } else {
      torrent = add_peer_to_torrent( hash, &peer );
      if( !torrent ) {
e500:
        return httperror(s,h,"500 Internal Server Error","A server error has occured. Please retry later.");
      }
      if( ( reply_size = return_peers_for_torrent( torrent, numwant, SUCCESS_HTTP_HEADER_LENGTH + static_scratch ) ) <= 0 )
        goto e500;
    }
    break;
  case 11:
    if( byte_diff(data,11,"mrtg_scrape"))
      goto e404;
    { 
      time_t seconds_elapsed = time( NULL ) - ot_start_time;
      reply_size = sprintf( static_scratch + SUCCESS_HTTP_HEADER_LENGTH, 
                            "%i\n%i\nUp: %i seconds (%i hours)\nPretuned by german engineers, currently handling %i connections per second.",
                            ot_overall_connections, ot_overall_connections, (int)seconds_elapsed,
                            (int)(seconds_elapsed / 3600), (int)ot_overall_connections / ( (int)seconds_elapsed ? (int)seconds_elapsed : 1 ) );
    }
    break;
  default: /* neither *scrape nor announce */
e404:
    return httperror(s,h,"404 Not Found","No such file or directory.");
  }

  if( reply_size ) {
    /* This one is rather ugly, so I take you step by step through it.

       1. In order to avoid having two buffers, one for header and one for content, we allow all above functions from trackerlogic to
       write to a fixed location, leaving SUCCESS_HTTP_HEADER_LENGTH bytes in our static buffer, which is enough for the static string
       plus dynamic space needed to expand our Content-Length value. We reserve SUCCESS_HTTP_SIZE_OFF for it expansion and calculate
       the space NOT needed to expand in reply_off
    */
    size_t reply_off = SUCCESS_HTTP_SIZE_OFF - snprintf( static_scratch, 0, "%zd", reply_size );

    /* 2. Now we sprintf our header so that sprintf writes its terminating '\0' exactly one byte before content starts. Complete
       packet size is increased by size of header plus one byte '\n', we  will copy over '\0' in next step */
    reply_size += 1 + sprintf( static_scratch + reply_off, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r", reply_size );

    /* 3. Finally we join both blocks neatly */
    static_scratch[ SUCCESS_HTTP_HEADER_LENGTH - 1 ] = '\n';

    senddata( s, h, static_scratch + reply_off, reply_size );
  } else {
    if( h ) array_reset(&h->r);
#ifdef _DEBUG_FDS
    if( !fd_debug_space[s] ) fprintf( stderr, "close on non-open fd\n" );
    fd_debug_space[s] = 0;
#endif
    free( h ); io_close( s );
  }
}

void graceful( int s ) {
  if( s == SIGINT ) {
    signal( SIGINT, SIG_IGN);
    deinit_logic();
    exit( 0 );
  }
}

#ifdef _DEBUG_FDS
void count_fds( int s ) {
  int i, count = 0;
  for( i=0; i<sizeof(fd_debug_space); ++i )
    if( fd_debug_space[i] ) ++count;
  fprintf( stderr, "Open fds here: %i\n", count );
}
#endif

void usage( char *name ) {
  fprintf( stderr, "Usage: %s [-i serverip] [-p serverport] [-d serverdirectory]"
#ifdef WANT_CLOSED_TRACKER
  " [-oc]"
#endif
#ifdef WANT_BLACKLIST
  " [-bB]"
#endif
  "\n", name );
}

void help( char *name ) {
  usage( name );
  fprintf( stderr, "\t-i serverip\tspecify ip to bind to (default: *)\n"
                   "\t-p serverport\tspecify port to bind to (default: 6969)\n"
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
);
}

void handle_read( int64 clientsocket ) {
  struct http_data* h = io_getcookie( clientsocket );
  int l = io_tryread( clientsocket, static_scratch, sizeof static_scratch );

  if( l <= 0 ) {
    if( h ) {
      array_reset(&h->r);
      free(h);
    }
#ifdef _DEBUG_FDS
    if( !fd_debug_space[clientsocket] ) fprintf( stderr, "close on non-open fd\n" );
    fd_debug_space[clientsocket] = 0;
#endif
    io_close(clientsocket);
    return;
  }

  array_catb(&h->r,static_scratch,l);

  if( array_failed(&h->r))
    httperror(clientsocket,h,"500 Server Error","Request too long.");
  else if (array_bytes(&h->r)>8192)
    httperror(clientsocket,h,"500 request too long","You sent too much headers");
  else if ((l=header_complete(h)))
    httpresponse(clientsocket,h);
}

void handle_write( int64 clientsocket ) {
  struct http_data* h=io_getcookie(clientsocket);
  if( !h ) return;
  if( iob_send( clientsocket, &h->batch ) <= 0 ) {
    iob_reset( &h->batch );
    io_close( clientsocket );
    free( h );
  }
}

void handle_accept( int64 serversocket ) {
  struct http_data* h;
  unsigned char ip[4];
  uint16 port;
  tai6464 t;
  int64 i;

  while( ( i = socket_accept4( serversocket, (char*)ip, &port) ) != -1 ) {

    if( !io_fd( i ) ||
        !(h = (struct http_data*)malloc(sizeof(struct http_data))) ) {
      io_close( i );
      continue;
    }

#ifdef _DEBUG_FDS
  if( fd_debug_space[i] ) fprintf( stderr, "double use of fd: %i\n", (int)i );
  fd_debug_space[i] = 1;
#endif

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
  else
    carp( "socket_accept4" );
}

void handle_timeouted( ) {
  int64 i;
  while( ( i = io_timeouted() ) != -1 ) {
    struct http_data* h=io_getcookie(i);
    if( h ) {
      array_reset( &h->r );
      free( h );
    }
#ifdef _DEBUG_FDS
    if( !fd_debug_space[i] ) fprintf( stderr, "close on non-open fd\n" );
    fd_debug_space[i] = 0;
#endif
    io_close(i);
  }
}

void server_mainloop( int64 serversocket ) {
  tai6464 t, next_timeout_check;

  io_wantread( serversocket );
  taia_now( &next_timeout_check );

  for (;;) {
    int64 i;

    taia_now(&t);
    taia_addsec(&t,&t,OT_CLIENT_TIMEOUT_CHECKINTERVAL);
    io_waituntil(t);

    while( ( i = io_canread() ) != -1 ) {
      if( i == serversocket )
        handle_accept( i );
      else
        handle_read( i );
    }

    while( ( i = io_canwrite() ) != -1 )
      handle_write( i );

    taia_now(&t);
    if( taia_less( &next_timeout_check, &t ) ) {
      handle_timeouted( );
      taia_now(&next_timeout_check);
      taia_addsec(&next_timeout_check,&next_timeout_check,OT_CLIENT_TIMEOUT_CHECKINTERVAL);
    }
  }
}

int main( int argc, char **argv ) {
  int64 s = socket_tcp4( );
  char *serverip = NULL;
  char *serverdir = ".";
  uint16 port = 6969;
  int scanon = 1;

  while( scanon ) {
    switch( getopt(argc,argv,":i:p:d:ocbBh") ) {
      case -1 : scanon = 0; break;
      case 'i': serverip = optarg; break;
      case 'p': port = (uint16)atol( optarg ); break;
      case 'd': serverdir = optarg; break;
      case 'h': help( argv[0]); exit(0);
#ifdef WANT_CLOSED_TRACKER
      case 'o': g_closedtracker = 0; break;
      case 'c': g_closedtracker = 1; break;
#endif
#ifdef WANT_BLACKLIST
      case 'b': g_check_blacklist = 1; break;
      case 'B': g_check_blacklist = 0; break;
#endif
      default:
      case '?': usage( argv[0] ); exit(1);
    }
  }

  if (socket_bind4_reuse(s,serverip,port)==-1)
    panic("socket_bind4_reuse");

  setegid((gid_t)-2); setuid((uid_t)-2);
  setgid((gid_t)-2); seteuid((uid_t)-2);

  if (socket_listen(s,SOMAXCONN)==-1)
    panic("socket_listen");

  if (!io_fd(s))
    panic("io_fd");

  signal( SIGPIPE, SIG_IGN );
  signal( SIGINT,  graceful );
#ifdef _DEBUG_FDS
  signal( SIGINFO, count_fds );
#endif
  if( init_logic( serverdir ) == -1 )
    panic("Logic not started");

  ot_start_time = time( NULL );

  server_mainloop(s);

  return 0;
}
