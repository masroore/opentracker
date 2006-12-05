#include "socket.h"
#include "io.h"
#include "buffer.h"
#include "ip6.h"
#include "array.h"
#include "case.h"
#include "fmt.h"
#include "iob.h"
#include "str.h"
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
  int keepalive;
};

int header_complete(struct http_data* r) {
  long i;
  long l=array_bytes(&r->r);
  const char* c=array_start(&r->r);
  for (i=0; i+1<l; ++i) {
    if (c[i]=='\n' && c[i+1]=='\n')
      return i+2;
    if (i+3<l &&
	c[i]=='\r' && c[i+1]=='\n' &&
	c[i+2]=='\r' && c[i+3]=='\n')
      return i+4;
  }
  return 0;
}

void httperror(struct http_data* r,const char* title,const char* message) {
  char* c;
  c=r->hdrbuf=(char*)malloc(strlen(message)+strlen(title)+200);
  if (!c) {
    r->hdrbuf="HTTP/1.0 500 internal error\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nout of memory\n";
    r->hlen=strlen(r->hdrbuf);
  } else {
    c+=fmt_str(c,"HTTP/1.0 ");
    c+=fmt_str(c,title);
    c+=fmt_str(c,"\r\nContent-Type: text/html\r\nConnection: ");
    c+=fmt_str(c,r->keepalive?"keep-alive":"close");
    c+=fmt_str(c,"\r\nContent-Length: ");
    c+=fmt_ulong(c,strlen(message)+strlen(title)+16-4);
    c+=fmt_str(c,"\r\n\r\n<title>");
    c+=fmt_str(c,title+4);
    c+=fmt_str(c,"</title>\n");
    r->hlen=c - r->hdrbuf;
  }
  iob_addbuf(&r->iob,r->hdrbuf,r->hlen);
}

static struct mimeentry { const char* name, *type; } mimetab[] = {
  { "html",	"text/html" },
  { "css",	"text/css" },
  { "dvi",	"application/x-dvi" },
  { "ps",	"application/postscript" },
  { "pdf",	"application/pdf" },
  { "gif",	"image/gif" },
  { "png",	"image/png" },
  { "jpeg",	"image/jpeg" },
  { "jpg",	"image/jpeg" },
  { "mpeg",	"video/mpeg" },
  { "mpg",	"video/mpeg" },
  { "avi",	"video/x-msvideo" },
  { "mov",	"video/quicktime" },
  { "qt",	"video/quicktime" },
  { "mp3",	"audio/mpeg" },
  { "ogg",	"audio/x-oggvorbis" },
  { "wav",	"audio/x-wav" },
  { "pac",	"application/x-ns-proxy-autoconfig" },
  { "sig",	"application/pgp-signature" },
  { "torrent",	"application/x-bittorrent" },
  { "class",	"application/octet-stream" },
  { "js",	"application/x-javascript" },
  { "tar",	"application/x-tar" },
  { "zip",	"application/zip" },
  { "dtd",	"text/xml" },
  { "xml",	"text/xml" },
  { "xbm",	"image/x-xbitmap" },
  { "xpm",	"image/x-xpixmap" },
  { "xwd",	"image/x-xwindowdump" },
  { 0,0 } };

const char* mimetype(const char* filename) {
  int i,e=str_rchr(filename,'.');
  if (filename[e]==0) return "text/plain";
  ++e;
  for (i=0; mimetab[i].name; ++i)
    if (str_equal(mimetab[i].name,filename+e))
      return mimetab[i].type;
  return "application/octet-stream";
}

const char* http_header(struct http_data* r,const char* h) {
  long i;
  long l=array_bytes(&r->r);
  long sl=strlen(h);
  const char* c=array_start(&r->r);
  for (i=0; i+sl+2<l; ++i)
    if (c[i]=='\n' && case_equalb(c+i+1,sl,h) && c[i+sl+1]==':') {
      c+=i+sl+1;
      if (*c==' ' || *c=='\t') ++c;
      return c;
    }
  return 0;
}

void httpresponse(struct http_data* h,int64 s) {
  char* c;
  const char* m;
  array_cat0(&h->r);
  c=array_start(&h->r);
  if (byte_diff(c,4,"GET ")) {
e400:
    httperror(h,"400 Invalid Request","This server only understands GET.");
  } else {
    char *d;
    int64 fd;
    struct stat s;
    c+=4;
    for (d=c; *d!=' '&&*d!='\t'&&*d!='\n'&&*d!='\r'; ++d) ;
    if (*d!=' ') goto e400;
    *d=0;
    if (c[0]!='/') goto e404;
    while (c[1]=='/') ++c;
    if (!io_readfile(&fd,c+1)) {
e404:
      httperror(h,"404 Not Found","No such file or directory.");
    } else {
      if (fstat(fd,&s)==-1) {
	io_close(fd);
	goto e404;
      }
      if ((m=http_header(h,"Connection"))) {
	if (str_equal(m,"keep-alive"))
	  h->keepalive=1;
	else
	  h->keepalive=0;
      } else {
	if (byte_equal(d+1,8,"HTTP/1.0"))
	  h->keepalive=0;
	else
	  h->keepalive=1;
      }
      m=mimetype(c);
      c=h->hdrbuf=(char*)malloc(500);
      c+=fmt_str(c,"HTTP/1.1 Coming Up\r\nContent-Type: ");
      c+=fmt_str(c,m);
      c+=fmt_str(c,"\r\nContent-Length: ");
      c+=fmt_ulonglong(c,s.st_size);
      c+=fmt_str(c,"\r\nLast-Modified: ");
      c+=fmt_httpdate(c,s.st_mtime);
      c+=fmt_str(c,"\r\nConnection: ");
      c+=fmt_str(c,h->keepalive?"keep-alive":"close");
      c+=fmt_str(c,"\r\n\r\n");
      iob_addbuf(&h->iob,h->hdrbuf,c - h->hdrbuf);
      iob_addfile(&h->iob,fd,0,s.st_size);
    }
  }
  io_dontwantread(s);
  io_wantwrite(s);
}

int main() {
  int s=socket_tcp6b();
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
  for (;;) {
    int64 i;
    io_wait();
    while ((i=io_canread())!=-1) {
      if (i==s) {
	int n;
	while ((n=socket_accept6(s,ip,&port,&scope_id))!=-1) {
	  char buf[IP6_FMT];
	  buffer_puts(buffer_2,"accepted new connection from ");
	  buffer_put(buffer_2,buf,fmt_ip6(buf,ip));
	  buffer_puts(buffer_2,":");
	  buffer_putulong(buffer_2,port);
	  buffer_puts(buffer_2," (fd ");
	  buffer_putulong(buffer_2,n);
	  buffer_puts(buffer_2,")");
	  if (io_fd(n)) {
	    struct http_data* h=(struct http_data*)malloc(sizeof(struct http_data));
	    io_wantread(n);
	    if (h) {
	      byte_zero(h,sizeof(struct http_data));
	      io_setcookie(n,h);
	    } else
	      io_close(n);
	  } else {
	    buffer_puts(buffer_2,", but io_fd failed.");
	    io_close(n);
	  }
	  buffer_putnlflush(buffer_2);
	}
	if (errno==EAGAIN)
	  io_eagain(s);
	else
	  carp("socket_accept6");
      } else {
	char buf[8192];
	struct http_data* h=io_getcookie(i);
	int l=io_tryread(i,buf,sizeof buf);
	if (l==-3) {
	  if (h) {
	    array_reset(&h->r);
	    iob_reset(&h->iob);
	    free(h->hdrbuf); h->hdrbuf=0;
	  }
	  buffer_puts(buffer_2,"io_tryread(");
	  buffer_putulong(buffer_2,i);
	  buffer_puts(buffer_2,"): ");
	  buffer_puterror(buffer_2);
	  buffer_putnlflush(buffer_2);
	  io_close(i);
	} else if (l==0) {
	  if (h) {
	    array_reset(&h->r);
	    iob_reset(&h->iob);
	    free(h->hdrbuf); h->hdrbuf=0;
	  }
	  buffer_puts(buffer_2,"eof on fd #");
	  buffer_putulong(buffer_2,i);
	  buffer_putnlflush(buffer_2);
	  io_close(i);
	} else if (l>0) {
	  array_catb(&h->r,buf,l);
	  if (array_failed(&h->r)) {
	    httperror(h,"500 Server Error","request too long.");
emerge:
	    io_dontwantread(i);
	    io_wantwrite(i);
	  } else if (array_bytes(&h->r)>8192) {
	    httperror(h,"500 request too long","You sent too much headers");
	    goto emerge;
	  } else if ((l=header_complete(h)))
	    httpresponse(h,i);
	}
      }
    }
    while ((i=io_canwrite())!=-1) {
      struct http_data* h=io_getcookie(i);
      int64 r=iob_send(i,&h->iob);
/*      printf("iob_send returned %lld\n",r); */
      if (r==-1) io_eagain(i); else
      if (r<=0) {
	array_trunc(&h->r);
	iob_reset(&h->iob);
	free(h->hdrbuf); h->hdrbuf=0;
	if (h->keepalive) {
	  io_dontwantwrite(i);
	  io_wantread(i);
	} else
	  io_close(i);
      }
    }
  }
  return 0;
}
