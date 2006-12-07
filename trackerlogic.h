#ifndef __TRACKERLOGIC_H__
#define __TRACKERLOGIC_H__

/* Should be called BYTE, WORD, DWORD - but some OSs already have that and there's no #iftypedef */
/* They mark memory used as data instead of integer or human readable string -
   they should be cast before used as integer/text */
typedef unsigned char  ot_byte;
typedef unsigned short ot_word;
typedef unsigned long  ot_dword;

typedef unsigned long  ot_time;
typedef ot_byte        ot_hash[20];
typedef ot_byte        ot_ip[ 4/*0*/ ];
// tunables
const unsigned long OT_TIMEOUT          = 2700;
const unsigned long OT_HUGE_FILESIZE    = 1024*1024*256; // Thats 256MB per file, enough for 204800 peers of 128 bytes

// We will not service v6, yes
#define OT_COMPACT_ONLY

#define MEMMOVE              memmove
#define BZERO                bzero
#define FORMAT_FIXED_STRING  sprintf
#define FORMAT_FORMAT_STRING sprintf
#define BINARY_FIND          binary_search
#define NOW                  time(NULL)

typedef struct ot_peer {
#ifndef OT_COMPACT_ONLY
  ot_hash id;
  ot_hash key;
#endif
  ot_ip   ip;
  ot_word port;
  ot_time death;
  ot_byte flags;
} *ot_peer;
ot_byte PEER_FLAG_SEEDING   = 0x80;
ot_byte PEER_IP_LENGTH_MASK = 0x3f;

typedef struct {
  ot_hash       hash;
  ot_peer       peer_list;
  unsigned long peer_count;
  unsigned long seed_count;
} *ot_torrent;

void *map_file( char *file_name );
void  unmap_file( char *file_name, void *map, unsigned long real_size );

// This behaves quite like bsearch but allows to find
// the insertion point for inserts after unsuccessful searches
// in this case exactmatch is 0 on exit
//
void *binary_search( const void *key, const void *base,
                     const unsigned long member_count, const unsigned long member_size,
                     int (*compar) (const void *, const void *),
                     int *exactmatch );

//
// Exported functions
//

int  init_logic( char *chdir_directory );
void deinit_logic( );

ot_torrent add_peer_to_torrent( ot_hash hash, ot_peer peer );
void return_peers_for_torrent( ot_torrent torrent, unsigned long amount, char *reply );
void heal_torrent( ot_torrent torrent );

#endif
