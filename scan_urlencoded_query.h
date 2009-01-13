/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifndef __SCAN_URLENCODED_QUERY_H__
#define __SCAN_URLENCODED_QUERY_H__

#include <sys/types.h>

typedef struct {
  char *key;
  int   value;
} ot_keywords;

typedef enum {
  SCAN_PATH                  = 1,
  SCAN_SEARCHPATH_PARAM      = 2,
  SCAN_SEARCHPATH_VALUE      = 4,
  SCAN_SEARCHPATH_TERMINATOR = 8
} SCAN_SEARCHPATH_FLAG;

/* string     in: pointer to source
              out: pointer to next scan position
   deststring pointer to destination
   flags      determines, what to parse
   returns    number of valid converted characters in deststring
              or -1 for parse error
              or -2 for terminator found
*/
ssize_t scan_urlencoded_query(char **string, char *deststring, SCAN_SEARCHPATH_FLAG flags);

/* string     in: pointer to source
              out: pointer to next scan position
   flags      determines, what to parse
   returns    value for matched keyword
              or -1 for parse error
              or -2 for terminator found
              or -3 for no keyword matched
 */
int scan_find_keywords( const ot_keywords * keywords, char **string, SCAN_SEARCHPATH_FLAG flags);

/* string     in: pointer to value of a param=value pair to skip
              out: pointer to next scan position on return
*/
void scan_urlencoded_skipvalue( char **string );

/* data       pointer to len chars of string
 len        length of chars in data to parse
 number     number to receive result
 returns    number of bytes not parsed, mostly !=0 means fail
 */
ssize_t scan_fixed_int( char *data, size_t len, int *number );

#endif
