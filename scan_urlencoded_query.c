#include "scan.h"
#include "scan_urlencoded_query.h"

// Idea is to do a in place replacement or guarantee at least
// strlen( string ) bytes in deststring
// watch http://www.ietf.org/rfc/rfc2396.txt
//       unreserved    = alphanum | mark
//       mark          = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
// we add '%' to the matrix to not stop at encoded chars.

static const unsigned char reserved_matrix[] = { 0xA2, 0x63, 0xFF, 0x03, 0xFE, 0xFF, 0xFF, 0x87, 0xFE, 0xFF, 0xFF, 0x47};
inline int is_unreserved( unsigned char c ) {
  if( ( c <= 32 ) || ( c >= 127 ) ) return 0; return 1&(reserved_matrix[(c-32)>>3]>>(c&7));
}

size_t scan_urlencoded_query(char **string, char *deststring, int flags) {
  register const unsigned char* s=*(const unsigned char**) string;
  unsigned char *d = (unsigned char*)deststring;
  register unsigned char b, c;

  while ( is_unreserved( c = *s++) ) {
    if (c=='%') {
      if( ( c = scan_fromhex(*s++) ) == 0xff ) return -1;
      if( ( b = scan_fromhex(*s++) ) == 0xff ) return -1;
      c=(c<<4)|b;
    }
    if(d) *d++ = c;
  }

  switch( c ) {
  case 0: case '\r': case '\n': case ' ':
    if( d == (unsigned char*)deststring ) return -2;
    --s;
    break;
  case '?':
    if( flags != SCAN_PATH ) return -1;
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
