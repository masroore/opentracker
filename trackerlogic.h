/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __TRACKERLOGIC_H__
#define __TRACKERLOGIC_H__

#include <sys/types.h>
#include <sys/time.h>
#include <time.h>

/* Should be called BYTE, WORD, DWORD - but some OSs already have that and there's no #iftypedef */
/* They mark memory used as data instead of integer or human readable string -
   they should be cast before used as integer/text */
typedef unsigned char  ot_byte;
typedef unsigned short ot_word;
typedef unsigned long  ot_dword;

typedef ot_byte        ot_hash[20];
typedef ot_dword       ot_ip;
typedef time_t         ot_time;

/* Some tracker behaviour tunable */
#define OT_CLIENT_TIMEOUT 30
#define OT_CLIENT_TIMEOUT_CHECKINTERVAL 5
#define OT_CLIENT_REQUEST_INTERVAL 1800
#define OT_CLIENT_REQUEST_VARIATION 180

#define OT_CLIENT_REQUEST_INTERVAL_RANDOM ( OT_CLIENT_REQUEST_INTERVAL + (int)( random( ) % OT_CLIENT_REQUEST_VARIATION ) )

/* We maintain a list of 256 pointers to sorted list of ot_torrent structs
   Sort key is, of course, its hash */

/* This list points to 9 pools of peers each grouped in five-minute-intervals
   thus achieving a timeout of 2700s or 45 minutes
   These pools are sorted by its binary content */

#define OT_POOLS_COUNT   9
#define OT_POOLS_TIMEOUT 300
#define NOW              (time(NULL)/OT_POOLS_TIMEOUT)

#define OT_VECTOR_MIN_MEMBERS   128
#define OT_VECTOR_GROW_RATIO    2
#define OT_VECTOR_SHRINK_THRESH 3
#define OT_VECTOR_SHRINK_RATIO  2
typedef struct {
  void   *data;
  size_t  size;
  size_t  space;
} ot_vector;

typedef struct {
  ot_byte data[8];
} ot_peer;
static const ot_byte PEER_FLAG_SEEDING   = 0x80;
static const ot_byte PEER_FLAG_COMPLETED = 0x40;
static const ot_byte PEER_FLAG_STOPPED   = 0x20;

#define OT_SETIP( peer, ip ) memmove((peer),(ip),4);
#define OT_SETPORT( peer, port ) memmove(((ot_byte*)peer)+4,(port),2);
#define OT_FLAG(peer) (((ot_byte*)(peer))[6])

#define OT_PEER_COMPARE_SIZE ((size_t)6)
#define OT_HASH_COMPARE_SIZE (sizeof(ot_hash))

typedef struct {
  ot_time        base;
  size_t         seed_count[ OT_POOLS_COUNT ];
  size_t         downloaded;
  ot_vector      peers[ OT_POOLS_COUNT ];
} ot_peerlist;

typedef struct {
  ot_hash      hash;
  ot_peerlist *peer_list;
} ot_torrent;

/*
   Exported functions
*/

int  init_logic( const char * const serverdir );
void deinit_logic( void );

#ifdef WANT_CLOSED_TRACKER
extern int g_closedtracker;
#endif
#ifdef WANT_BLACKLIST
extern int g_check_blacklist;
#endif

enum { STATS_MRTG, STATS_TOP5, STATS_DMEM };

ot_torrent *add_peer_to_torrent( ot_hash *hash, ot_peer *peer );
size_t return_peers_for_torrent( ot_torrent *torrent, size_t amount, char *reply );
size_t return_fullscrape_for_tracker( char **reply );
size_t return_scrape_for_torrent( ot_hash *hash, char *reply );
size_t return_sync_for_torrent( ot_hash *hash, char **reply );
size_t return_stats_for_tracker( char *reply, int mode );
size_t return_memstat_for_tracker( char **reply );
void  remove_peer_from_torrent( ot_hash *hash, ot_peer *peer );

#endif
