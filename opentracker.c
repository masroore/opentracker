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
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>

#include "trackerlogic.h"
#include "scan_urlencoded_query.h"

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
  char ip[16];
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
    char *c, *d, *data, *reply = NULL;
    struct ot_peer peer;
    ot_torrent torrent;
    ot_hash *hash = NULL;
    unsigned long numwant;
    int compact, scanon;
    size_t reply_size = 0;

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
      break;
    case 8: 
      if( byte_diff(data,8,"announce"))
        goto e404;
      byte_copy( &peer.ip, 4, h->ip );
      peer.port_flags = 6881 << 16;
      numwant = 50;
      compact = 1;
      scanon = 1;

      while( scanon ) {
        switch( scan_urlencoded_query( &c, data = c, SCAN_SEARCHPATH_PARAM ) ) {
        case -2: /* terminator */
          scanon = 0;
          break;
        case -1: /* error */
          goto e404;
        case 4:
          if(!byte_diff(data,4,"port"))
            /* scan int */  c;
          else if(!byte_diff(data,4,"left"))
            /* scan int */  c;
          else
            scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          break;
        case 7:
          if(!byte_diff(data,7,"numwant"))
            /* scan int */  c;
          else if(!byte_diff(data,7,"compact"))
            /* scan flag */  c;
          else
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
            hash = (ot_hash*)data; /* Fall through intended */
            printf("hash: %s\n",*hash);
          default:
            continue;
          }
        default:
          scan_urlencoded_query( &c, NULL, SCAN_SEARCHPATH_VALUE );
          break;
        }
      }

      /* Scanned whole query string */
      if( !hash || ( compact == 0 ) ) goto e404;
      printf("ALLFINE\n");
      torrent = add_peer_to_torrent( hash, &peer );
      if( !torrent ) {
e500:
        httperror(h,"500 Internal Server Error","A server error has occured. Please retry later.");
        goto bailout;
      }
      reply = malloc( numwant*6+10 );
      if( reply )
        reply_size = return_peers_for_torrent( torrent, numwant, reply );
      if( !reply || ( reply_size < 0 ) ) {
        if( reply ) free( reply );
        goto e500;
      }
      break;
    default: /* neither scrape nor announce */
e404:
      httperror(h,"404 Not Found","No such file or directory.");
      goto bailout;
    }
    c=h->hdrbuf=(char*)malloc(500);
    c+=fmt_str(c,"HTTP/1.1 Coming Up\r\nContent-Type: text/plain");
    c+=fmt_str(c,"\r\nContent-Length: ");
    /* ANSWER SIZE*/
    c+=fmt_ulonglong(c, 100 );
    c+=fmt_str(c,"\r\nLast-Modified: ");
    /* MODIFY DATE
    c+=fmt_httpdate(c,s.st_mtime); */
    c+=fmt_str(c,"\r\nConnection: close\r\n\r\n");
    iob_addbuf(&h->iob,h->hdrbuf,c - h->hdrbuf);
    if( reply && reply_size ) iob_addbuf(&h->iob,reply, reply_size );

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
    int s=socket_tcp6();
    uint32 scope_id;
    char ip[16];
    uint16 port;

    if (socket_bind6_reuse(s,V6any,6969,0)==-1)
        panic("socket_bind6_reuse");

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
                while ((n=socket_accept6(s,ip,&port,&scope_id))!=-1)
                {
                    if (io_fd(n))
                    {
                        struct http_data* h=(struct http_data*)malloc(sizeof(struct http_data));
                        io_wantread(n);

                        if (h)
                        {
                            byte_zero(h,sizeof(struct http_data));
                            byte_copy(h->ip,sizeof(ip),ip);
                            io_setcookie(n,h);
                        } else
                            io_close(n);
                    } else
                        io_close(n);
                    buffer_putnlflush(buffer_2);
                }
                if (errno==EAGAIN)
                    io_eagain(s);
                else
                    carp("socket_accept6");
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
