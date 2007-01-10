/* This software was written by Dirk Engling <erdgeist@erdgeist.org> 
   It is considered beerware. Prost. Skol. Cheers or whatever.
   Some of the stuff below is stolen from Fefes example libowfat httpd.
*/

#include "socket.h"
#include "io.h"
#include "buffer.h"
#include "ip6.h"
#include "array.h"
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

unsigned long const OT_CLIENT_TIMEOUT = 15;
unsigned long const OT_CLIENT_TIMEOUT_CHECKINTERVAL = 5;

static unsigned int ot_overall_connections = 0;
static time_t ot_start_time;
static const unsigned int SUCCESS_HTTP_HEADER_LENGTH = 80;
static const unsigned int SUCCESS_HTTP_SIZE_OFF = 17;
// To always have space for error messages
static char static_reply[8192];

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
  array r;
  unsigned long ip;
};

int header_complete(struct http_data* r) {
  long l = array_bytes(&r->r);
  const char* c = array_start(&r->r);
  long i;

  for (i=0; i+1<l; ++i) {
    if (c[i]=='\n' && c[i+1]=='\n') return i+2;
    if (i+3<l && c[i]=='\r' && c[i+1]=='\n' && c[i+2]=='\r' && c[i+3]=='\n') return i+4;
  }
  return 0;
}

// whoever sends data is not interested in its input-array
void senddata(int64 s, struct http_data* h, char *buffer, size_t size ) {
  size_t written_size;

  if( h ) array_reset(&h->r);
  written_size = write( s, buffer, size );
  if( ( written_size < 0 ) || ( written_size == size ) ) {
    free(h); io_close( s );
  } else {
    // here we would take a copy of the buffer and remember it
    fprintf( stderr, "Should have handled this.\n" );
    free(h); io_close( s );
  }
}

void httperror(int64 s,struct http_data* h,const char* title,const char* message) {
  size_t reply_size = sprintf( static_reply, "HTTP/1.0 %s\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: %zd\r\n\r\n<title>%s</title>\n",
                        title, strlen(message)+strlen(title)+16-4,title+4);
  senddata(s,h,static_reply,reply_size);
}

// bestimmten http parameter auslesen und adresse zurueckgeben
const char* http_header(struct http_data* r,const char* h) {
    long i;

    long l = array_bytes(&r->r);
    long sl = strlen(h);
    const char* c = array_start(&r->r);

    for (i=0; i+sl+2<l; ++i)
    {
        if (c[i]=='\n' && case_equalb(c+i+1,sl,h) && c[i+sl+1]==':')
        {
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
    char       *c, *data; // must be enough
    ot_peer     peer;
    ot_torrent *torrent;
    ot_hash    *hash = NULL;
    int         numwant, tmp, scanon;
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

    switch( scan_urlencoded_query( &c, data = c, SCAN_PATH ) )
    {
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

      /* Scanned whole query string, wo */
      if( !hash )
        return httperror(s,h,"400 Invalid Request","This server only serves specific scrapes.");

      // Enough for http header + whole scrape string
      if( ( reply_size = return_scrape_for_torrent( hash, SUCCESS_HTTP_HEADER_LENGTH + static_reply ) ) <= 0 )
        goto e500;
      break;
    case 8: 
      if( byte_diff(data,8,"announce"))
        goto e404;

      OT_SETIP( &peer, &h->ip);
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
          default: // Fall through intended
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
        MEMMOVE( static_reply + SUCCESS_HTTP_HEADER_LENGTH, "d15:warning message4:Okaye", reply_size = 26 );
      } else {
        torrent = add_peer_to_torrent( hash, &peer );
        if( !torrent ) {
e500:
          return httperror(s,h,"500 Internal Server Error","A server error has occured. Please retry later.");
        }
        if( ( reply_size = return_peers_for_torrent( torrent, numwant, SUCCESS_HTTP_HEADER_LENGTH + static_reply ) ) <= 0 )
          goto e500;
      }
      break;
    case 11:
      if( byte_diff(data,11,"mrtg_scrape"))
        goto e404;
      { 
        unsigned long seconds_elapsed = time( NULL ) - ot_start_time;
        reply_size = sprintf( static_reply + SUCCESS_HTTP_HEADER_LENGTH, 
                              "%d\n%d\nUp: %ld seconds (%ld hours)\nPretuned by german engineers, currently handling %li connections per second.",
                              ot_overall_connections, ot_overall_connections, seconds_elapsed,
                              seconds_elapsed / 3600, ot_overall_connections / ( seconds_elapsed ? seconds_elapsed : 1 ) );
      }
      break;
    default: /* neither *scrape nor announce */
e404:
      return httperror(s,h,"404 Not Found","No such file or directory.");
    }

    if( reply_size ) {
      size_t reply_off = SUCCESS_HTTP_SIZE_OFF - snprintf( static_reply, 0, "%zd", reply_size );
      reply_size += 1 + sprintf( static_reply + reply_off, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r", reply_size );
      static_reply[ SUCCESS_HTTP_HEADER_LENGTH - 1 ] = '\n';
      senddata( s, h, static_reply + reply_off, reply_size );
    } else {
      if( h ) array_reset(&h->r);
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

int main( int argc, char **argv ) {
  int s=socket_tcp4();
  tai6464 t, next_timeout_check;
  unsigned long ip;
  char *serverip = NULL;
  char *serverdir = ".";
  uint16 port = 6969;

  while( 1 ) {
    switch( getopt(argc,argv,":i:p:d:ocbBh") ) {
      case -1: goto allparsed;
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

allparsed:
  ot_start_time = time( NULL );
  if (socket_bind4_reuse(s,serverip,port)==-1)
    panic("socket_bind4_reuse");

  if (socket_listen(s,16)==-1)
    panic("socket_listen");

  if (!io_fd(s))
    panic("io_fd");

  signal( SIGPIPE, SIG_IGN );
  signal( SIGINT, graceful );
  if( init_logic( serverdir ) == -1 )
    panic("Logic not started");

  io_wantread( s );
  taia_now( &next_timeout_check );
  taia_addsec( &next_timeout_check, &next_timeout_check, OT_CLIENT_TIMEOUT_CHECKINTERVAL );

  for (;;) {
    int64 i;
    taia_now(&t);
    taia_addsec(&t,&t,OT_CLIENT_TIMEOUT_CHECKINTERVAL);
    io_waituntil(t);

    taia_now(&t);
    if( taia_less( &next_timeout_check, &t ) ) {
      while( ( i = io_timeouted() ) != -1 ) {
        struct http_data* h=io_getcookie(i);
        if( h ) {
          array_reset( &h->r );
          free( h );
        }
        io_close(i);
      }
      taia_now(&next_timeout_check);
      taia_addsec(&next_timeout_check,&next_timeout_check,OT_CLIENT_TIMEOUT_CHECKINTERVAL);
    }

    while( ( i = io_canread() ) != -1 ) {
      if( i == s ) { // ist es der serversocket?
        int n;
        while( ( n = socket_accept4( s, (void*)&ip, &port) ) != -1 ) {
          if( io_fd( n ) ) {
            struct http_data* h=(struct http_data*)malloc(sizeof(struct http_data));
            io_wantread(n);

            if (h) {
              byte_zero(h,sizeof(struct http_data));
              h->ip=ip;
              taia_now(&t);
              taia_addsec(&t,&t,OT_CLIENT_TIMEOUT);
              io_timeout(n,t);
              io_setcookie(n,h);
              ++ot_overall_connections;
            } else
              io_close(n);
          } else
            io_close(n);
        }
        if( errno==EAGAIN )
          io_eagain(s);
        else
          carp("socket_accept4");
      } else {
        char buf[8192];
        struct http_data* h=io_getcookie(i);

        int l=io_tryread(i,buf,sizeof buf);
        if( l <= 0 ) {
          if( h ) {
            array_reset(&h->r);
            free(h);
          }
          io_close(i);
        } else {
          array_catb(&h->r,buf,l);

          if( array_failed(&h->r))
            httperror(i,h,"500 Server Error","Request too long.");
          else if (array_bytes(&h->r)>8192)
            httperror(i,h,"500 request too long","You sent too much headers");
          else if ((l=header_complete(h)))
            httpresponse(i,h);
          else {
            taia_now(&t);
            taia_addsec(&t,&t,OT_CLIENT_TIMEOUT);
            io_timeout(i,t);
          }
        }
      }
    }
  }
  return 0;
}
