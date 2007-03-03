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

static const unsigned char reserved_matrix_strict[] = { 0xA2, 0x67, 0xFF, 0x03, 0xFE, 0xFF, 0xFF, 0x87, 0xFE, 0xFF, 0xFF, 0x47};
*/
static const unsigned char reserved_matrix[] = { 0xA2, 0xFF, 0xFF, 0x5F, 0xFE, 0xFF, 0xFF, 0x87, 0xFE, 0xFF, 0xFF, 0x47};

static int is_unreserved( unsigned char c ) {
  if( ( c <= 32 ) || ( c >= 127 ) ) return 0; return 1&(reserved_matrix[(c-32)>>3]>>(c&7));
}

ssize_t scan_urlencoded_query(char **string, char *deststring, int flags) {
  register const unsigned char* s=*(const unsigned char**) string;
  unsigned char *d = (unsigned char*)deststring;
  register unsigned char b, c;

retry_parsing:
  while( is_unreserved( c = *s++) ) {
    if( c=='%') {
      if( ( c = scan_fromhex(*s++) ) == 0xff ) return -1;
      if( ( b = scan_fromhex(*s++) ) == 0xff ) return -1;
      c=(c<<4)|b;
    }
    if( d ) *d++ = c;
  }

  switch( c ) {
  case 0: case '\r': case '\n': case ' ':
    if( d == (unsigned char*)deststring ) return -2;
    --s;
    break;
  case '?':
    if( flags == SCAN_PATH ) goto found_terminator;
    if( d ) *d++ = c;
    goto retry_parsing;
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

found_terminator:
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
    if( j == len ) return len;
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
