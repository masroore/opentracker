/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* Opentracker */
#include "scan_urlencoded_query.h"

/* Libwofat */
#include "scan.h"

/* System */
#include <string.h>

/* Idea is to do a in place replacement or guarantee at least
   strlen( string ) bytes in deststring
   watch http://www.ietf.org/rfc/rfc2396.txt
         unreserved    = alphanum | mark
         mark          = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
   we add '%' to the matrix to not stop at encoded chars.
   After losing too many requests to being too strict, add the following characters to reserved matrix
         relax         = "+" | "," | "/" | ";" | "<" | ">" | ":"
*/

/* This matrix holds for each ascii character the information,
   whether it is a non-terminating character for on of the three
   scan states we are in, that is 'path', 'param' and 'value' from
  /path?param=value&param=value, it is encoded in bit 0, 1 and 2
  respectively

  The top bit of lower nibble indicates, whether this character is
  a hard terminator, ie. \0, \n or \s, where the whole scanning
  process should terminate
  */
static const unsigned char is_unreserved[256] = {
  8,0,0,0,0,0,0,0,0,0,8,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  8,7,8,8,8,7,0,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,4,7,6,
  4,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,8,8,8,7,
  8,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,8,8,7,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

/* Do a fast nibble to hex representation conversion */
static unsigned char fromhex(unsigned char x) {
  x-='0'; if( x<=9) return x;
  x&=~0x20; x-='A'-'0';
  if( x<6 ) return x+10;
  return 0xff;
}

/* Skip the value of a param=value pair */
void scan_urlencoded_skipvalue( char **string ) {
  const unsigned char* s=*(const unsigned char**) string;
  unsigned char f;

  /* Since we are asked to skip the 'value', we assume to stop at
     terminators for a 'value' string position */
  while( ( f = is_unreserved[ *s++ ] ) & SCAN_SEARCHPATH_VALUE );

  /* If we stopped at a hard terminator like \0 or \n, make the
     next scan_urlencoded_query encounter it again */
  if( f & SCAN_SEARCHPATH_TERMINATOR ) --s;

  *string = (char*)s;
}

int scan_find_keywords( const ot_keywords * keywords, char **string, SCAN_SEARCHPATH_FLAG flags) {
  char *deststring = *string;
  ssize_t match_length = scan_urlencoded_query(string, deststring, flags );

  if( match_length < 0 ) return match_length;
  if( match_length == 0 ) return -3;

  while( keywords->key ) {
    if( !strncmp( keywords->key, deststring, match_length ) && !keywords->key[match_length] )
      return keywords->value;
    keywords++;
  }

  return -3;
}

ssize_t scan_urlencoded_query(char **string, char *deststring, SCAN_SEARCHPATH_FLAG flags) {
  const unsigned char* s=*(const unsigned char**) string;
  unsigned char *d = (unsigned char*)deststring;
  unsigned char b, c;

  /* This is the main decoding loop.
    'flag' determines, which characters are non-terminating in current context
    (ie. stop at '=' and '&' if scanning for a 'param'; stop at '?' if scanning for the path )
  */
  while( is_unreserved[ c = *s++ ] & flags ) {

    /* When encountering an url escaped character, try to decode */
    if( c=='%') {
      if( ( b = fromhex(*s++) ) == 0xff ) return -1;
      if( ( c = fromhex(*s++) ) == 0xff ) return -1;
      c|=(b<<4);
    }

    /* Write (possibly decoded) character to output */
    *d++ = c;
  }

  switch( c ) {
  case 0: case '\r': case '\n': case ' ':
    /* If we started scanning on a hard terminator, indicate we've finished */
    if( d == (unsigned char*)deststring ) return -2;

    /* Else make the next call to scan_urlencoded_param encounter it again */
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

ssize_t scan_fixed_int( char *data, size_t len, int *tmp ) {
  int minus = 0;
  *tmp = 0;
  if( *data == '-' ) --len, ++data, ++minus;
  while( (len > 0) && (*data >= '0') && (*data <= '9') ) { --len; *tmp = 10**tmp + *data++-'0'; }
  if( minus ) *tmp = -*tmp;
  return len;
}

const char *g_version_scan_urlencoded_query_c = "$Source$: $Revision$\n";
