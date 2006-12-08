#ifndef  __SCAN_URLENCODED_QUERY_H__
#define __SCAN_URLENCODED_QUERY_H__

#define BREAK_AT_QUESTIONMARK (1<<0)
#define BREAK_AT_WHITESPACE   (1<<1)
#define BREAK_AT_AMPERSAND    (1<<2)
#define BREAK_AT_EQUALSIGN    (1<<3)

#define SCAN_PATH             ( BREAK_AT_QUESTIONMARK | BREAK_AT_WHITESPACE )
#define SCAN_SEARCHPATH_PARAM ( BREAK_AT_EQUALSIGN )
#define SCAN_SEARCHPATH_VALUE ( BREAK_AT_AMPERSAND | BREAK_AT_WHITESPACE )

// string     pointer to source, pointer to after terminator on return
// deststring pointer to destination
// flags      determines, what to parse
// returns    number of valid converted characters in deststring
//            or -1 for parse error
size_t scan_urlencoded_query(char **string, char *deststring, int flags);

#endif
