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

#endif
