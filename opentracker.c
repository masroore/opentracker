#include "socket.h"
#include "io.h"
#include "buffer.h"
#include "ip6.h"
#include "array.h"
#include "case.h"
#include "fmt.h"
#include "iob.h"
#include "str.h"
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>

#include "trackerlogic.h"
#include "scan_urlencoded_query.h"

static unsigned int ot_overall_connections = 0;
static time_t ot_start_time;

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
  io_batch iob;
  char* hdrbuf;
  int hlen;
  unsigned long ip;
};

int header_complete(struct http_data* r)
{
    long i;

    long l = array_bytes(&r->r);
    const char* c = array_start(&r->r);

    for (i=0; i+1<l; ++i)
    {
        if (c[i]=='\n' && c[i+1]=='\n')
            return i+2;

        if (i+3<l && c[i]=='\r' && c[i+1]=='\n' && c[i+2]=='\r' && c[i+3]=='\n')
            return i+4;
    }
    return 0;
}

void httperror(struct http_data* r,const char* title,const char* message)
{
    char* c;
    c=r->hdrbuf=(char*)malloc(strlen(message)+strlen(title)+200);
    
    if (!c)
    {
        r->hdrbuf="HTTP/1.0 500 internal error\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nout of memory\n";
        r->hlen=strlen(r->hdrbuf);
    }
    else
    {
        c+=fmt_str(c,"HTTP/1.0 ");
        c+=fmt_str(c,title);
        c+=fmt_str(c,"\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: ");
        c+=fmt_ulong(c,strlen(message)+strlen(title)+16-4);
        c+=fmt_str(c,"\r\n\r\n<title>");
        c+=fmt_str(c,title+4);
        c+=fmt_str(c,"</title>\n");
        r->hlen=c - r->hdrbuf;
    }
    iob_addbuf(&r->iob,r->hdrbuf,r->hlen);
}

// bestimmten http parameter auslesen und adresse zurueckgeben

const char* http_header(struct http_data* r,const char* h)
{
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

void httpresponse(struct http_data* h,int64 s)
{
    char       *c, *d, *data, *reply = NULL;
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
        httperror(h,"400 Invalid Request","This server only understands GET.");
        goto bailout;
    }

    c+=4;
    for (d=c; *d!=' '&&*d!='\t'&&*d!='\n'&&*d!='\r'; ++d) ;

    if (*d!=' ') goto e400;
    *d=0;
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
          switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) ) {
          case -1:
            goto e404;
          case 20:
            hash = (ot_hash*)data; /* Fall through intended */
          default:
            continue;
          }
        default:
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          break;
        }
      }

      /* Scanned whole query string, wo */
      if( !hash ) {
        httperror(h,"400 Invalid Request","This server only serves specific scrapes.");
        goto bailout;
      }

      // Enough for whole scrape string
      reply = malloc( 128 );
      if( reply )
        reply_size = return_scrape_for_torrent( hash, reply );
      if( !reply || ( reply_size < 0 ) ) {
        if( reply ) free( reply );
        goto e500;
      }
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
        case 4:
          if(!byte_diff(data,4,"port")) {
            size_t len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
            if( ( len <= 0 ) || scan_fixed_int( data, len, &tmp ) || ( tmp > 0xffff ) ) goto e404;
            port = htons( tmp ); OT_SETPORT ( &peer, &port );
          } else if(!byte_diff(data,4,"left")) {
            size_t len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
            if( ( len <= 0 ) || scan_fixed_int( data, len, &tmp ) ) goto e404;
            if( !tmp ) OT_FLAG( &peer ) |= PEER_FLAG_SEEDING;
          } else
            scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          break;
        case 5:
          if(byte_diff(data,5,"event"))
            scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          else switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) ) {
          case -1:
            goto e404;
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
            if( ( len <= 0 ) || scan_fixed_int( data, len, &numwant ) ) goto e404;
          } else if(!byte_diff(data,7,"compact")) {
            size_t len = scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE );
            if( ( len <= 0 ) || scan_fixed_int( data, len, &tmp ) ) goto e404;
            if( !tmp ) {
              httperror(h,"400 Invalid Request","This server only delivers compact results.");
              goto bailout;
            }
          } else
            scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          break;
        case 9:
          if(byte_diff(data,9,"info_hash")) {
            scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
            continue;
          }
          /* ignore this, when we have less than 20 bytes */
          switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_VALUE ) ) {
          case -1:
            goto e404;
          case 20:
            hash = (ot_hash*)data;
          default: // Fall through intended
            continue;
          }
        default:
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          break;
        }
      }

      /* Scanned whole query string */
      if( !hash ) goto e404;

      if( OT_FLAG( &peer ) & PEER_FLAG_STOPPED ) {
        remove_peer_from_torrent( hash, &peer );
        reply = strdup( "d15:warning message4:Okaye" ); reply_size = 26;
      } else {
        torrent = add_peer_to_torrent( hash, &peer );
        if( !torrent ) {
e500:
          httperror(h,"500 Internal Server Error","A server error has occured. Please retry later.");
          goto bailout;
        }
        reply = malloc( numwant*6+128 ); // peerlist + seeder, peers and lametta n*6+81 a.t.m.
        if( reply )
          reply_size = return_peers_for_torrent( torrent, numwant, reply );
        if( !reply || ( reply_size < 0 ) ) {
          if( reply ) free( reply );
          goto e500;
        }
      }
      break;
    case 11:
      if( byte_diff(data,11,"mrtg_scrape"))
        goto e404;
      reply = malloc( 128 );
      { 
        unsigned long seconds_elapsed = time( NULL ) - ot_start_time;
        reply_size = sprintf( reply, "%d\n%d\nUp: %ld seconds (%ld hours)\nPretuned by german engineers, currently handling %li connections per second.",
        ot_overall_connections, ot_overall_connections, seconds_elapsed, seconds_elapsed / 3600, ot_overall_connections / ( seconds_elapsed ? seconds_elapsed : 1 ) );
      }
      break;
    default: /* neither *scrape nor announce */
e404:
      httperror(h,"404 Not Found","No such file or directory.");
      goto bailout;
    }

    c=h->hdrbuf=(char*)malloc(80);
    c+=fmt_str(c,"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ");
    c+=fmt_ulonglong(c, reply_size );
    c+=fmt_str(c,"\r\n\r\n");
    iob_addbuf(&h->iob,h->hdrbuf,c - h->hdrbuf);
    if( reply && reply_size ) iob_addbuf_free(&h->iob,reply, reply_size );

bailout:
    io_dontwantread(s);
    io_wantwrite(s);
}

void graceful( int s ) {
  if( s == SIGINT ) {
    signal( SIGINT, SIG_IGN);
    deinit_logic();
    exit( 0 );
  }
}

int main()
{
    int s=socket_tcp4();
    unsigned long ip;
    uint16 port;

    ot_start_time = time( NULL );
    if (socket_bind4_reuse(s,NULL,6969)==-1)
        panic("socket_bind4_reuse");

    if (socket_listen(s,16)==-1)
        panic("socket_listen");

    if (!io_fd(s))
        panic("io_fd");

    signal( SIGINT, graceful );
    if( init_logic( "." ) == -1 )
      panic("Logic not started");

    io_wantread(s);

    for (;;)
    {
        int64 i;
        io_wait();

        while ((i=io_canread())!=-1)
        {
            if (i==s)    // ist es der serversocket?
            {
                int n;
                while ((n=socket_accept4(s,(void*)&ip,&port))!=-1)
                {
                    if (io_fd(n))
                    {
                        struct http_data* h=(struct http_data*)malloc(sizeof(struct http_data));
                        io_wantread(n);

                        if (h)
                        {
                            byte_zero(h,sizeof(struct http_data));
                            h->ip=ip;
                            io_setcookie(n,h);
                            ++ot_overall_connections;
                        } else
                            io_close(n);
                    } else
                        io_close(n);
                }
                if (errno==EAGAIN)
                    io_eagain(s);
                else
                    carp("socket_accept4");
            }
            else
            {
                char buf[8192];
                struct http_data* h=io_getcookie(i);

                int l=io_tryread(i,buf,sizeof buf);
                if (l<=0)
                {
                    if (h)
                    {
                        array_reset(&h->r);
                        iob_reset(&h->iob);
                        free(h->hdrbuf); h->hdrbuf=0;
                    }
                    io_close(i);
                }
                else
                {
                    array_catb(&h->r,buf,l);

                    if (array_failed(&h->r))
                    {
                        httperror(h,"500 Server Error","request too long.");
emerge:
                        io_dontwantread(i);
                        io_wantwrite(i);
                    }
                    else if (array_bytes(&h->r)>8192)
                    {
                        httperror(h,"500 request too long","You sent too much headers");
                        goto emerge;
                    }
                    else if ((l=header_complete(h)))
                    {
                        httpresponse(h,i);
                    }
                }
            }
        }

        while ((i=io_canwrite())!=-1)
        {
            struct http_data* h=io_getcookie(i);

            int64 r=iob_send(i,&h->iob);

            if (r==-1)
                io_eagain(i);
            else
                if (r<=0)
                {
                    array_trunc(&h->r);
                    iob_reset(&h->iob);
                    free(h->hdrbuf); h->hdrbuf=0;
                    io_close(i);
                }
        }
    }
    return 0;
}
