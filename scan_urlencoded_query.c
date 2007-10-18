/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include "scan.h"
#include "scan_urlencoded_query.h"

/* Idea is to do a in place replacement or guarantee at least
   strlen( string ) bytes in deststring
   watch http://www.ietf.org/rfc/rfc2396.txt
         unreserved    = alphanum | mark
         mark          = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
   we add '%' to the matrix to not stop at encoded chars.
   After losing too many requests to being too strict, add the following characters to reserved matrix
         relax         = "+" | "," | "/" | ";" | "<" | ">" | ":"
*/

static const unsigned char is_unreserved[256] = {
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,1,0,0,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,0,
  0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,
  0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,1,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static unsigned char fromhex(unsigned char x) {
  x-='0'; if( x<=9) return x;
  x&=~0x20; x-='A'-'0';
  if( x<6 ) return x+10;
  return 0xff;
}

ssize_t scan_urlencoded_query(char **string, char *deststring, int flags) {
  const unsigned char* s=*(const unsigned char**) string;
  unsigned char *d = (unsigned char*)deststring;
  register unsigned char b, c;

retry_parsing:
  while( is_unreserved[ c = *s++ ] ) {
    if( c=='%') {
      if( ( b = fromhex(*s++) ) == 0xff ) return -1;
      if( ( c = fromhex(*s++) ) == 0xff ) return -1;
      c|=(b<<4);
    }
    if( d ) *d++ = c;
  }

  switch( c ) {
  case 0: case '\r': case '\n': case ' ':
    if( d && ( d == (unsigned char*)deststring ) ) return -2;
    --s;
    break;
  case '?':
    if( flags != SCAN_PATH ) {
      if( d ) *d++ = c;
      goto retry_parsing;
    }
    break;
  case '=':
    if( flags != SCAN_SEARCHPATH_PARAM ) return -1;
    break;
  case '&':
    if( flags == SCAN_PATH ) return -1;
    if( flags == SCAN_SEARCHPATH_PARAM ) --s;
    break;
  default:
    return -1;
  }

  *string = (char *)s;
  return d - (unsigned char*)deststring;
}

ssize_t scan_fixed_int( char *data, size_t len, int *tmp ) {
  *tmp = 0;
  while( (len > 0) && (*data >= '0') && (*data <= '9') ) { --len; *tmp = 10**tmp + *data++-'0'; }
  return len;
}

ssize_t scan_fixed_ip( char *data, size_t len, unsigned char ip[4] ) {
  int u, i;

  for( i=0; i<4; ++i ) {
    ssize_t j = scan_fixed_int( data, len, &u );
    if( j == (ssize_t)len ) return len;
    ip[i] = u;
    data += len - j;
    len = j;
    if ( i<3 ) {
      if( !len || *data != '.') return -1;
      --len; ++data;
    }
  }
  return len;
}
