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
  8,0,0,0,0,0,0,0,0,0,8,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,7,8,8,8,7,0,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,4,7,6,
  4,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,8,8,8,7,
  8,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,8,8,7,0,
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

void scan_urlencoded_skipvalue( char **string ) {
  const unsigned char* s=*(const unsigned char**) string;
  unsigned char f;

  while( ( f = is_unreserved[ *s++ ] ) & SCAN_SEARCHPATH_VALUE );
  if( f & SCAN_SEARCHPATH_TERMINATOR ) --s;
  *string = (char*)s;
}

ssize_t scan_urlencoded_query(char **string, char *deststring, SCAN_SEARCHPATH_FLAG flags) {
  const unsigned char* s=*(const unsigned char**) string;
  unsigned char *d = (unsigned char*)deststring;
  unsigned char b, c, f;

  while( ( f = is_unreserved[ c = *s++ ] ) & flags ) {
    if( c=='%') {
      if( ( b = fromhex(*s++) ) == 0xff ) return -1;
      if( ( c = fromhex(*s++) ) == 0xff ) return -1;
      c|=(b<<4);
    }
    *d++ = c;
  }

  switch( c ) {
  case 0: case '\r': case '\n': case ' ':
    if( d == (unsigned char*)deststring ) return -2;
    --s;
    break;
  case '?':
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
  int minus = 0;
  *tmp = 0;
  if( *data == '-' ) --len, ++data, ++minus;
  while( (len > 0) && (*data >= '0') && (*data <= '9') ) { --len; *tmp = 10**tmp + *data++-'0'; }
  if( minus ) *tmp = -*tmp;
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
