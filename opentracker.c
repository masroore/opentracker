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
}

void httpresponse(struct http_data* h,int64 s)
{
    char* c;
    array_cat0(&h->r);

    c = array_start(&h->r);

    if (byte_diff(c,4,"GET "))
    {
e400:
        httperror(h,"400 Invalid Request","This server only understands GET.");
    }
    else
    {
        char *d;
        int64 fd;
        struct stat s;
        
        // expect 'GET /uri?nnbjhg HTTP/1.*'
        c+=4;

        for (d=c; *d!=' '&&*d!='\t'&&*d!='\n'&&*d!='\r'; ++d) ;

        if (*d!=' ') goto e400;
        *d=0;
        if (c[0]!='/') goto e404;
        while (c[1]=='/') ++c;

        data = c;
        switch( scan_urlencoded_query( &c, data, SCAN_PATH ) ) {
        case 6: /* scrape ? */
          if (!byte_diff(c,6,"scrape"))
            goto 404;
          break;
        case 9:
          if( !byte_diff(c,8,"announce"))
            goto 404;
          else {
            // info_hash, left, port, numwant, compact            
            struct ot_peer peer;
            ot_hash hash;
            byte_copy( peer.ip, h->ip, 4);
            peer.port = 6881;

            while( NOCHAMSCANNEN ) {
              data = c;
              switch( scan_urlencoded_query( &c, data, SCAN_SEARCHPATH_PARAM ) ) {
              case -1: /* error */
                httperror(h,"404 Not Found","No such file or directory.");
                goto e404;
              case 4:
                if(!byte_diff(c,4,"port"))
                  /* scan int */
                else if(!byte_diff(c,4,"left"))
                  /* scan int */
                break;
              case 7:
                if(!byte_diff(c,7,"numwant"))
                  /* scan int */
                else if(!byte_diff(c,7,"compact"))
                  /* scan flag */
                break; 
              case 9: /* info_hash */
                if(!byte_diff(c,9,"info_hash"))
                  /* scan 20 bytes */
                break; 
            }
          }
          break;
        default: /* neither scrape nor announce */
          httperror(h,"404 Not Found","No such file or directory.");
          goto e404;
        }

        c=h->hdrbuf=(char*)malloc(500);
        c+=fmt_str(c,"HTTP/1.1 Coming Up\r\nContent-Type: text/plain");
        c+=fmt_str(c,"\r\nContent-Length: ");
        /* ANSWER SIZE*/
        c+=fmt_ulonglong(c,s.st_size);
        c+=fmt_str(c,"\r\nLast-Modified: ");
        /* MODIFY DATE */
        c+=fmt_httpdate(c,s.st_mtime);
        c+=fmt_str(c,"\r\nConnection: close\r\n\r\n");
        iob_addbuf(&h->iob,h->hdrbuf,c - h->hdrbuf);
        iob_addbuf(&h->iob,tracker_answer, tzracker_answer_size);
    }
e404:
    io_dontwantread(s);
    io_wantwrite(s);
}

int main()
{
    int s=socket_tcp6();
    uint32 scope_id;
    char ip[16];
    uint16 port;

    if (socket_bind6_reuse(s,V6any,8000,0)==-1)
        panic("socket_bind6_reuse");

    if (socket_listen(s,16)==-1)
        panic("socket_listen");

    if (!io_fd(s))
        panic("io_fd");

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
                            byte_copy(h->ip,ip,sizeof(ip));
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
