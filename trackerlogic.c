// THIS REALLY BELONGS INTO A HEADER FILE
//
//
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>

typedef unsigned char ot_hash[20];
typedef unsigned char ot_ip[ 4/*0*/ ];
typedef unsigned long ot_time;
// tunables
const unsigned long OT_TIMEOUT          = 2700;
const unsigned long OT_HUGE_FILESIZE    = 1024*1024*256; // Thats 256MB per file, enough for 204800 peers of 128 bytes

#define OT_COMPACT_ONLY

#define MEMMOVE              memmove
#define BZERO                bzero
#define FORMAT_FIXED_STRING  sprintf
#define FORMAT_FORMAT_STRING sprintf
#define BINARY_FIND          binary_search

typedef struct {
#ifndef OT_COMPACT_ONLY
  ot_hash         id;
  ot_hash         key;
#endif
  ot_ip           ip;
  unsigned short  port;
  ot_time         death;
  unsigned char   flags;
} ot_peer;
unsigned char PEER_FLAG_SEEDING   = 0x80;
unsigned char PEER_IP_LENGTH_MASK = 0x3f;

typedef struct {
  ot_hash         hash;
  ot_peer        *peer_list;
  unsigned long   peer_count;
  unsigned long   seed_count;
} ot_torrent;

void *map_file( char *file_name );

// This behaves quite like bsearch but allows to find
// the insertion point for inserts after unsuccessful searches
// in this case exactmatch is 0 on exit
//
void *binary_search( const void *key, const void *base,
                     const unsigned long member_count, const unsigned long member_size,
                     int (*compar) (const void *, const void *),
                     int *exactmatch );

int compare_hash( const void *hash1, const void *hash2 ) { return memcmp( hash1, hash2, sizeof( ot_hash )); }
int compare_ip_port( const void *peer1, const void *peer2 ) { return memcmp( peer1, peer2, 6); }

//
//
// END OF STUFF THAT BELONGS INTO A HEADER FILE

ot_torrent *torrents_pointer = 0;
unsigned long torrents_count = 0;
unsigned char *scratchspace;

ot_torrent *add_peer_to_torrent( ot_hash hash, ot_peer *peer ) {
  ot_torrent *torrent;
  ot_peer    *peer_dest;
  int exactmatch;

  torrent = BINARY_FIND( hash, torrents_pointer, torrents_count, sizeof( ot_torrent ), compare_hash, &exactmatch );
  if( !exactmatch ) {
    // Assume, OS will provide us with space, after all, this is file backed
    MEMMOVE( torrent + 1, torrent, ( torrents_pointer + torrents_count ) - torrent );

    // Create a new torrent entry, then
    MEMMOVE( &torrent->hash, hash, sizeof( ot_hash ) );
    torrent->peer_list  = map_file( hash );
    torrent->peer_count = 0;
    torrent->seed_count = 0;
  }

  peer_dest = BINARY_FIND( peer, torrent->peer_list, torrent->peer_count, sizeof( ot_peer ), compare_ip_port, &exactmatch );
  if( exactmatch ) {
    // If peer was a seeder but isn't anymore, decrease seeder count
    if( ( peer_dest->flags & PEER_FLAG_SEEDING ) && !( peer->flags & PEER_FLAG_SEEDING ) )
      torrent->seed_count--;
    if( !( peer_dest->flags & PEER_FLAG_SEEDING ) && ( peer->flags & PEER_FLAG_SEEDING ) )
      torrent->seed_count++;
  } else {
    // Assume, OS will provide us with space, after all, this is file backed
    MEMMOVE( peer_dest + 1, peer_dest, ( torrent->peer_list + torrent->peer_count ) - peer_dest );

    // Create a new peer entry, then
    MEMMOVE( peer_dest, peer, sizeof( ot_peer ) );

    torrent->peer_count++;
    torrent->seed_count+= ( peer->flags & PEER_FLAG_SEEDING ) ? 1 : 0;
  }

  // Set new time out time
  peer_dest->death = now() + OT_TIMEOUT;

  return torrent;
}

#define SETINVALID( i )   (scratchspace[index] = 3);
#define SETSELECTED( i )  (scratchspace[index] = 1);
#define TESTSELECTED( i ) (scratchspace[index] == 1 )
#define TESTSET( i )      (scratchspace[index])
#define RANDOM            random()

inline int TESTVALIDPEER( ot_peer *p ) { return p->death > now(); }

// Compiles a list of random peers for a torrent
// * scratch space keeps track of death or already selected peers
// * reply must have enough space to hold 1+(1+16+2+1)*amount+1 bytes
// * Selector function can be anything, maybe test for seeds, etc.
// * that RANDOM may return huge values
// * does not yet check not to return self
// * it is not guaranteed to see all peers, so no assumptions on active seeders/peers may be done
// * since compact format cannot handle v6 addresses, it must be enabled by OT_COMPACT_ONLY
//
void return_peers_for_torrent( ot_torrent *torrent, unsigned long amount, char *reply ) {
  register ot_peer *peer_base = torrent->peer_list;
  unsigned long     peer_count = torrent->peer_count;
  unsigned long     selected_count = 0, invalid_count = 0;
  unsigned long     index = 0;

  // optimize later ;)
  BZERO( scratchspace, peer_count );

  while( ( selected_count < amount ) && ( selected_count + invalid_count < peer_count ) ) {
    // skip to first non-flagged peer
    while( TESTSET(index) ) index = ( index + 1 ) % peer_count;

    if( TESTVALIDPEER( peer_base + index ) ) {
      SETINVALID(index); invalid_count++;
    } else {
      SETSELECTED(index); selected_count++;
      index = ( index + RANDOM ) % peer_count;
    }
  }

  // Now our scratchspace contains a list of selected_count valid peers
  // Collect them into a reply string
  index = 0;

#ifndef OT_COMPACT_ONLY
  reply += FORMAT_FIXED_STRING( reply, "d5:peersl" );
#else
  reply += FORMAT_FORMAT_STRING( reply, "d5:peers%i:",6*selected_count );
#endif

  while( selected_count-- ) {
    ot_peer *peer;
    while( !TESTSELECTED( index ) ) ++index;
    peer = peer_base + index;
#ifdef OT_COMPACT_ONLY
    MEMMOVE( reply, &peer->ip, 4 );
    MEMMOVE( reply+4, &peer->port, 2 );
    reply += 6;
#else
    reply += FORMAT_FORMAT_STRING( reply, "d2:ip%d:%s7:peer id20:%20c4:porti%ie",
      peer->flags & PEER_IP_LENGTH_MASK,
      peer->ip,
      peer->id,
      peer->port );
#endif
  }
#ifndef OT_COMPACT_ONLY
  reply += FORMAT_FIXED_STRING( reply, "ee" );
#else
  reply += FORMAT_FIXED_STRING( reply, "e" );
#endif
}

// Compacts a torrents peer list
// * torrents older than OT_TIMEOUT are being kicked
// * is rather expansive
// * if this fails, torrent file is invalid, should add flag
//
void heal_torrent( ot_torrent *torrent ) {
  unsigned long index = 0, base = 0, end, seed_count = 0;

  // Initialize base to first dead peer.
  while( ( base < torrent->peer_count ) && torrent->peer_list[base].death <= now() ) {
    seed_count += ( torrent->peer_list[base].flags & PEER_FLAG_SEEDING ) ? 1 : 0;
    base++;
  }

  // No dead peers? Home.
  if( base == torrent->peer_count ) return;

  // From now index always looks to the next living peer while base keeps track of
  // the dead peer that marks the beginning of insert space.
  index = base + 1;

  while( 1 ) {
    // Let index search for next living peer
    while( ( index < torrent->peer_count ) && torrent->peer_list[index].death > now() ) index++;

    // No further living peers found - base is our new peer count
    if( index == torrent->peer_count ) {
      torrent->peer_count = base;
      torrent->seed_count = seed_count;
      return;
    }

    end = index + 1;

    // Let end search for next dead peer (end of living peers)
    while( ( end < torrent->peer_count ) && torrent->peer_list[end].death <= now() ) {
      seed_count += ( torrent->peer_list[end].flags & PEER_FLAG_SEEDING ) ? 1 : 0;
      end++;
    }

    // We either hit a dead peer or the end of our peers
    // In both cases: move block towards base
    MEMMOVE( torrent->peer_list + base, torrent->peer_list + index, ( end - index ) * sizeof( ot_peer ) );
    base += end - index;

    index = end;
  }
}

void *binary_search( const void *key, const void *base,
                     unsigned long member_count, const unsigned long member_size,
                     int (*compar) (const void *, const void *),
                     int *exactmatch ) {
  unsigned char *lookat = ((unsigned char*)base) + member_size * (member_count >> 1);
  *exactmatch = 1;

  while( member_count ) {
    int cmp = compar((void*)lookat, key);
    if (cmp == 0) return (void *)lookat;
    if (cmp < 0) {
      base = (void*)(lookat + member_size);
      --member_count;
    }
    member_count >>= 1;
    lookat = ((unsigned char*)base) + member_size * (member_count >> 1);
  }
  *exactmatch = 0;
  return (void*)lookat;

}

// This function maps a "huge" file into process space
// * I guess, we should be checking for more errors...
void *map_file( char *file_name ) {
  char *map;
  int file_desc=open(file_name,O_RDWR|O_CREAT|O_NDELAY,0644);

  if( file_desc < 0) return 0;

  map=mmap(0,OT_HUGE_FILESIZE,PROT_READ|PROT_WRITE,MAP_SHARED,file_desc,0);
  close(file_desc);

  return (map == (char*)-1) ? 0 : map;
}

int init_logic( ) {
  unlink( "./opentracker_map_index.idx" );
  torrents_pointer = map_file( "./opentracker_map_index.idx" );
  torrents_count   = 0;
  scratchspace     = map_file( "./scratchspace" );
}

void deinit_logic( ) {
  unmap_file( torrents_pointer );
}
