#include "trackerlogic.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <glob.h>

// Helper functions for binary_find
//
int compare_hash( const void *hash1, const void *hash2 ) { return memcmp( hash1, hash2, sizeof( ot_hash )); }
int compare_ip_port( const void *peer1, const void *peer2 ) { return memcmp( &((ot_peer)peer1)->ip, &((ot_peer)peer2)->ip, 6); }

void *binary_search( const void *key, const void *base,
                     unsigned long member_count, const unsigned long member_size,
                     int (*compar) (const void *, const void *),
                     int *exactmatch ) {
  ot_byte *lookat = ((ot_byte*)base) + member_size * (member_count >> 1);
  *exactmatch = 1;

  while( member_count ) {
    int cmp = compar((void*)lookat, key);
    if (cmp == 0) return (void *)lookat;
    if (cmp < 0) {
      base = (void*)(lookat + member_size);
      --member_count;
    }
    member_count >>= 1;
    lookat = ((ot_byte*)base) + member_size * (member_count >> 1);
  }
  *exactmatch = 0;
  return (void*)lookat;

}

// Converter function from memory to human readable hex strings
// * definitely not thread safe!!!
//
char ths[1+2*20];char *to_hex(ot_byte*s){char*m="0123456789ABCDEF";char*e=ths+40;char*t=ths;while(t<e){*t++=m[*s>>4];*t++=m[*s++&15];}*t=0;return ths;}

// GLOBAL VARIABLES
//
unsigned long torrents_count = 0;
ot_torrent    torrents_list  = 0;
ot_byte       *scratch_space = 0;

#define SETINVALID( i )   (scratch_space[index] = 3);
#define SETSELECTED( i )  (scratch_space[index] = 1);
#define TESTSELECTED( i ) (scratch_space[index] == 1 )
#define TESTSET( i )      (scratch_space[index])
#define RANDOM            random()

ot_torrent add_peer_to_torrent( ot_hash *hash, ot_peer peer ) {
  ot_torrent torrent;
  ot_peer    peer_dest;
  int        exactmatch;

  torrent = BINARY_FIND( hash, torrents_list, torrents_count, sizeof( *torrent ), compare_hash, &exactmatch );
  if( !exactmatch ) {
    // Assume, OS will provide us with space, after all, this is file backed
    MEMMOVE( torrent + 1, torrent, ( torrents_list + torrents_count ) - torrent );

    // Create a new torrent entry, then
    MEMMOVE( &torrent->hash, hash, sizeof( ot_hash ) );
    torrent->peer_list  = map_file( to_hex( *hash ) );
    torrent->peer_count = 0;
    torrent->seed_count = 0;
  }

  peer_dest = BINARY_FIND( peer, torrent->peer_list, torrent->peer_count, sizeof( *peer_dest ), compare_ip_port, &exactmatch );
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
  peer_dest->death = NOW + OT_TIMEOUT;

  return torrent;
}

inline int TESTVALIDPEER( ot_peer p ) { return p->death > NOW; }

// Compiles a list of random peers for a torrent
// * scratch space keeps track of death or already selected peers
// * reply must have enough space to hold 1+(1+16+2+1)*amount+1 bytes
// * Selector function can be anything, maybe test for seeds, etc.
// * that RANDOM may return huge values
// * does not yet check not to return self
// * it is not guaranteed to see all peers, so no assumptions on active seeders/peers may be done
// * since compact format cannot handle v6 addresses, it must be enabled by OT_COMPACT_ONLY
//
size_t return_peers_for_torrent( ot_torrent torrent, unsigned long amount, char *reply ) {
  register ot_peer peer_base = torrent->peer_list;
  char            *r = reply;
  unsigned long    peer_count = torrent->peer_count;
  unsigned long    selected_count = 0, invalid_count = 0;
  unsigned long    index = 0;

  // optimize later ;)
  BZERO( scratch_space, peer_count );

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
  r += FORMAT_FIXED_STRING( r, "d5:peersl" );
#else
  r += FORMAT_FORMAT_STRING( r, "d5:peers%li:",6*selected_count );
#endif

  while( selected_count-- ) {
    ot_peer peer;
    while( !TESTSELECTED( index ) ) ++index;
    peer = peer_base + index;
#ifdef OT_COMPACT_ONLY
    MEMMOVE( r, &peer->ip, 4 );
    MEMMOVE( r+4, &peer->port, 2 );
    r += 6;
#else
    r += FORMAT_FORMAT_STRING( r, "d2:ip%d:%s7:peer id20:%20c4:porti%ie",
      peer->flags & PEER_IP_LENGTH_MASK,
      peer->ip,
      peer->id,
      peer->port );
#endif
  }
#ifndef OT_COMPACT_ONLY
  r += FORMAT_FIXED_STRING( r, "ee" );
#else
  r += FORMAT_FIXED_STRING( r, "e" );
#endif
  return r - reply;
}

// Compacts a torrents peer list
// * torrents older than OT_TIMEOUT are being kicked
// * is rather expensive
// * if this fails, torrent file is invalid, should add flag
//
void heal_torrent( ot_torrent torrent ) {
  unsigned long index = 0, base = 0, end, seed_count = 0, now = NOW;

  // Initialize base to first dead peer.
  while( ( base < torrent->peer_count ) && torrent->peer_list[base].death <= now ) {
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
    while( ( index < torrent->peer_count ) && torrent->peer_list[index].death > now ) index++;

    // No further living peers found - base is our new peer count
    if( index == torrent->peer_count ) {
      torrent->peer_count = base;
      torrent->seed_count = seed_count;
      return;
    }

    end = index + 1;

    // Let end search for next dead peer (end of living peers)
    while( ( end < torrent->peer_count ) && torrent->peer_list[end].death <= now ) {
      seed_count += ( torrent->peer_list[end].flags & PEER_FLAG_SEEDING ) ? 1 : 0;
      end++;
    }

    // We either hit a dead peer or the end of our peers
    // In both cases: move block towards base
    MEMMOVE( torrent->peer_list + base, torrent->peer_list + index, ( end - index ) * sizeof( struct ot_peer ) );
    base += end - index;

    index = end;
  }
}

void dispose_torrent( ot_torrent torrent ) {
  unmap_file( NULL, torrent->peer_list, 0 );
  unlink( to_hex( torrent->hash ) );
  MEMMOVE( torrent, torrent + 1, ( torrents_list + torrents_count ) - ( torrent + 1 ) );
  torrents_count--;
}

// This function maps a "huge" file into process space
// * giving no name will aqcuire anonymous growable memory
// * memory will not be "freed" from systems vm if once used, until unmap_file
// * I guess, we should be checking for more errors...
//
void *map_file( char *file_name ) {
  char *map;
  if( file_name ) {
    int file_desc=open(file_name,O_RDWR|O_CREAT|O_NDELAY,0644);
printf( "%s\n", file_name );
    if( file_desc < 0) return 0;
    lseek( file_desc, OT_HUGE_FILESIZE, SEEK_SET );
    write( file_desc, "_", 1 );
    map=mmap(0,OT_HUGE_FILESIZE,PROT_READ|PROT_WRITE,MAP_SHARED,file_desc,0);
    close(file_desc);
  } else
    map=mmap(0,OT_HUGE_FILESIZE,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0);

  return (map == (char*)-1) ? 0 : map;
}

void unmap_file( char *file_name, void *map, unsigned long real_size ) {
  munmap( map, OT_HUGE_FILESIZE );
  if( file_name)
    truncate( file_name, real_size );
}

void count_peers_and_seeds( ot_peer peer_list, unsigned long *peers, unsigned long *seeds ) {
  *peers = *seeds = 0;
  if( peer_list[*peers].ip )
    do {
      *seeds += peer_list[*peers++].flags & PEER_FLAG_SEEDING ? 1 : 0;
    } while( compare_ip_port( peer_list + *peers, peer_list + *peers - 1 ) < 0 );
}

int init_logic( char *directory ) {
  glob_t globber;
  int i;

  if( directory )
   chdir( directory );

  scratch_space    = map_file( NULL );
  torrents_list    = map_file( NULL );
  torrents_count   = 0;

  if( !scratch_space || !torrents_list ) {
    if( scratch_space || torrents_list )
      unmap_file( NULL, scratch_space ? (void*)scratch_space : (void*)torrents_list, 0 );
    return -1;
  }

  // Scan directory for filenames in the form [0-9A-F]{20}
  // * I know this looks ugly, but I've seen A-F to match umlauts as well in strange locales
  // * lower case for .. better being safe than sorry, this is not expensive here :)
  if( !glob(
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    "[0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef][0-9ABCDEFabcdef]"
    , GLOB_NOCHECK, 0, &globber) )
  {
    for( i=0; i<globber.gl_matchc; ++i ) {
#ifdef _DEBUG
      printf( "Found dir: %s\n", globber.gl_pathv[i] );
#endif

      if( ( torrents_list[torrents_count].peer_list = map_file( globber.gl_pathv[i] ) ) ) {
        MEMMOVE( &torrents_list[torrents_count].hash, globber.gl_pathv[i], sizeof( ot_hash ) );
        count_peers_and_seeds( torrents_list[torrents_count].peer_list,
                              &torrents_list[torrents_count].peer_count,
                              &torrents_list[torrents_count].seed_count );
        torrents_count++;        
      }
    }
  }

  globfree( &globber );
  return 0;
}

void deinit_logic( ) {
  // For all torrents... blablabla
  while( torrents_count-- )
    unmap_file( to_hex(torrents_list[torrents_count].hash), torrents_list[torrents_count].peer_list, torrents_list[torrents_count].peer_count * sizeof(struct ot_peer) );
  unmap_file( NULL, torrents_list, 0 );
  unmap_file( NULL, scratch_space, 0 );
}
