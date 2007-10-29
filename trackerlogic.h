/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __TRACKERLOGIC_H__
#define __TRACKERLOGIC_H__

#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>

/* Should be called BYTE, WORD, DWORD - but some OSs already have that and there's no #iftypedef */
/* They mark memory used as data instead of integer or human readable string -
   they should be cast before used as integer/text */
typedef uint8_t  ot_byte;
typedef uint16_t ot_word;
typedef uint32_t ot_dword;

typedef ot_byte        ot_hash[20];
typedef ot_dword       ot_ip;
typedef time_t         ot_time;

#define OT_VECTOR_MIN_MEMBERS   4
#define OT_VECTOR_GROW_RATIO    8
#define OT_VECTOR_SHRINK_THRESH 6
#define OT_VECTOR_SHRINK_RATIO  4
typedef struct {
  void   *data;
  size_t  size;
  size_t  space;
} ot_vector;

/* Some tracker behaviour tunable */
#define OT_CLIENT_TIMEOUT 30
#define OT_CLIENT_TIMEOUT_CHECKINTERVAL 10
#define OT_CLIENT_TIMEOUT_SEND (60*15)
#define OT_CLIENT_REQUEST_INTERVAL (60*30)
#define OT_CLIENT_REQUEST_VARIATION (60*6)

#define OT_TORRENT_TIMEOUT_HOURS 24
#define OT_TORRENT_TIMEOUT ((60*60*OT_TORRENT_TIMEOUT_HOURS)/OT_POOLS_TIMEOUT)

#define OT_CLIENT_REQUEST_INTERVAL_RANDOM ( OT_CLIENT_REQUEST_INTERVAL - OT_CLIENT_REQUEST_VARIATION/2 + (int)( random( ) % OT_CLIENT_REQUEST_VARIATION ) )

/* We maintain a list of 4096 pointers to sorted list of ot_torrent structs
   Sort key is, of course, its hash */
#define OT_BUCKET_COUNT 1024
static inline ot_vector *hash_to_bucket( ot_vector *vectors, ot_hash *hash ) {
  unsigned char *local_hash = hash[0];
  return vectors + ( ( local_hash[0] << 2 ) | ( local_hash[1] >> 6 ) );
}

/* This list points to 9 pools of peers each grouped in five-minute-intervals
   thus achieving a timeout of 2700s or 45 minutes
   These pools are sorted by its binary content */

#define OT_POOLS_COUNT   9
#define OT_POOLS_TIMEOUT (60*5)

extern  time_t g_now;
#define NOW              (g_now/OT_POOLS_TIMEOUT)

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
  size_t         seed_count;
  size_t         peer_count;
  size_t         down_count;
  size_t         seed_counts[ OT_POOLS_COUNT ];
  ot_vector      peers[ OT_POOLS_COUNT ];
#ifdef WANT_TRACKER_SYNC
  ot_vector      changeset;
#endif
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

enum { STATS_MRTG, STATS_TOP5, STATS_DMEM, STATS_TCP, STATS_UDP, STATS_SLASH24S, STATS_SLASH24S_OLD, SYNC_IN, SYNC_OUT };

#ifdef WANT_TRACKER_SYNC
ot_torrent *add_peer_to_torrent( ot_hash *hash, ot_peer *peer, int from_changeset );
#else
ot_torrent *add_peer_to_torrent( ot_hash *hash, ot_peer *peer );
#endif
size_t remove_peer_from_torrent( ot_hash *hash, ot_peer *peer, char *reply, int is_tcp );
size_t return_peers_for_torrent( ot_torrent *torrent, size_t amount, char *reply, int is_tcp );
size_t return_fullscrape_for_tracker( char **reply );
size_t return_tcp_scrape_for_torrent( ot_hash *hash, int amount, char *reply );
size_t return_udp_scrape_for_torrent( ot_hash *hash, char *reply );
size_t return_stats_for_tracker( char *reply, int mode );
size_t return_stats_for_slash24s( char *reply, size_t amount, ot_dword thresh );
size_t return_stats_for_slash24s_old( char *reply, size_t amount, ot_dword thresh );
size_t return_memstat_for_tracker( char **reply );
void   clean_all_torrents( void );

#ifdef WANT_TRACKER_SYNC
size_t return_changeset_for_tracker( char **reply );
int    add_changeset_to_tracker( ot_byte *data, size_t len );
#endif

#if defined ( WANT_BLACKLISTING ) || defined ( WANT_CLOSED_TRACKER )
int    accesslist_addentry( ot_hash *hash );
void   accesslist_reset( void );
#endif

#endif
