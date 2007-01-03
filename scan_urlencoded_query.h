#ifndef __SCAN_URLENCODED_QUERY_H__
#define __SCAN_URLENCODED_QUERY_H__

#define SCAN_PATH             0
#define SCAN_SEARCHPATH_PARAM 1
#define SCAN_SEARCHPATH_VALUE 2

// string     pointer to source, pointer to after terminator on return
// deststring pointer to destination
// flags      determines, what to parse
// returns    number of valid converted characters in deststring
//            or -1 for parse error
size_t scan_urlencoded_query(char **string, char *deststring, int flags);

// data       pointer to len chars of string
// len        length of chars in data to parse
// number     number to receive result
// returns    number of bytes not parsed, mostly !=0 means fail
size_t scan_fixed_int( char *data, size_t len, int *number );

// data       pointer to len chars of string
// len        length of chars in data to parse
// ip         buffer to receive result
// returns    number of bytes not parsed, mostly !=0 means fail
size_t scan_fixed_ip( char *data, size_t len, unsigned char ip[4] );

#endif
