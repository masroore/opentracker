/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

/* Libowfat */
#include "byte.h"
#include "scan.h"
#include "ip6.h"
#include "mmap.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_accesslist.h"
#include "ot_vector.h"

/* GLOBAL VARIABLES */
#ifdef WANT_ACCESSLIST
       char    *g_accesslist_filename;
static ot_hash *g_accesslist;
static size_t   g_accesslist_size;

static int vector_compare_hash(const void *hash1, const void *hash2 ) {
  return memcmp( hash1, hash2, OT_HASH_COMPARE_SIZE );
}

void accesslist_deinit( void ) {
  free( g_accesslist );
  g_accesslist = 0;
  g_accesslist_size = 0;
}

/* Read initial access list */
static void accesslist_readfile( int sig ) {
  ot_hash *info_hash, *accesslist_new = NULL, *accesslist_old;
  char    *map, *map_end, *read_offs;
  size_t   maplen;

  if( sig != SIGHUP ) return;

  if( ( map = mmap_read( g_accesslist_filename, &maplen ) ) == NULL ) {
    char *wd = getcwd( NULL, 0 );
    fprintf( stderr, "Warning: Can't open accesslist file: %s (but will try to create it later, if necessary and possible).\nPWD: %s\n", g_accesslist_filename, wd );
    free( wd );
    return;
  }

  /* You need at least 41 bytes to pass an info_hash, make enough room
     for the maximum amount of them */
  info_hash = accesslist_new = malloc( ( maplen / 41 ) * 20 );
  if( !accesslist_new ) {
    fprintf( stderr, "Warning: Not enough memory to allocate %zd bytes for accesslist buffer. May succeed later.\n", ( maplen / 41 ) * 20 );
    return;
  }
  
  /* No use to scan if there's not enough room for another full info_hash */
  map_end = map + maplen - 40;
  read_offs = map;

  /* We do ignore anything that is not of the form "^[:xdigit:]{40}[^:xdigit:].*" */
  while( read_offs < map_end ) {
    int i;
    for( i=0; i<(int)sizeof(ot_hash); ++i ) {
      int eger = 16 * scan_fromhex( read_offs[ 2*i ] ) + scan_fromhex( read_offs[ 1 + 2*i ] );
      if( eger < 0 )
        continue;
      (*info_hash)[i] = eger;
    }

    read_offs += 40;

    /* Append accesslist to accesslist vector */
    if( scan_fromhex( *read_offs ) < 0 )
      ++info_hash;

    /* Find start of next line */
    while( read_offs < map_end && *(read_offs++) != '\n' );
  }
#ifdef _DEBUG
  fprintf( stderr, "Added %d info_hashes to accesslist\n", info_hash - accesslist_new );
#endif

  mmap_unmap( map, maplen);

  qsort( accesslist_new, info_hash - accesslist_new, sizeof( *info_hash ), vector_compare_hash );

  /* Now exchange the accesslist vector in the least race condition prone way */
  g_accesslist_size = 0;
  accesslist_old    = g_accesslist;
  g_accesslist      = accesslist_new;
  g_accesslist_size = info_hash - accesslist_new;
  free( accesslist_old );  
}

int accesslist_hashisvalid( ot_hash hash ) {
  void *exactmatch = bsearch( hash, g_accesslist, g_accesslist_size, OT_HASH_COMPARE_SIZE, vector_compare_hash );

#ifdef WANT_ACCESSLIST_BLACK
  return exactmatch == NULL;
#else
  return exactmatch != NULL;
#endif
}

void accesslist_init( ) {
  /* Passing "0" since read_blacklist_file also is SIGHUP handler */
  if( g_accesslist_filename ) {
    accesslist_readfile( SIGHUP );
    signal( SIGHUP, accesslist_readfile );
  }
}
#endif

static ot_ip6         g_adminip_addresses[OT_ADMINIP_MAX];
static ot_permissions g_adminip_permissions[OT_ADMINIP_MAX];
static unsigned int   g_adminip_count = 0;

int accesslist_blessip( ot_ip6 ip, ot_permissions permissions ) {
  if( g_adminip_count >= OT_ADMINIP_MAX )
    return -1;

  memcpy(g_adminip_addresses + g_adminip_count,ip,sizeof(ot_ip6));
  g_adminip_permissions[ g_adminip_count++ ] = permissions;

#ifdef _DEBUG
  {
    char _debug[512];
    int off = snprintf( _debug, sizeof(_debug), "Blessing ip address " );
    off += fmt_ip6c(_debug+off, ip );

    if( permissions & OT_PERMISSION_MAY_STAT       ) off += snprintf( _debug+off, 512-off, " may_fetch_stats" );
    if( permissions & OT_PERMISSION_MAY_LIVESYNC   ) off += snprintf( _debug+off, 512-off, " may_sync_live" );
    if( permissions & OT_PERMISSION_MAY_FULLSCRAPE ) off += snprintf( _debug+off, 512-off, " may_fetch_fullscrapes" );
    if( permissions & OT_PERMISSION_MAY_PROXY      ) off += snprintf( _debug+off, 512-off, " may_proxy" );
    if( !permissions ) off += snprintf( _debug+off, sizeof(_debug)-off, " nothing\n" );
    _debug[off++] = '.';
    write( 2, _debug, off );
  }
#endif

  return 0;
}

int accesslist_isblessed( ot_ip6 ip, ot_permissions permissions ) {
  unsigned int i;
  for( i=0; i<g_adminip_count; ++i )
    if( !memcmp( g_adminip_addresses + i, ip, sizeof(ot_ip6)) && ( g_adminip_permissions[ i ] & permissions ) )
      return 1;
  return 0;
}

const char *g_version_accesslist_c = "$Source$: $Revision$\n";
