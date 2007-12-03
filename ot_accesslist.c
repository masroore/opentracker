/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

/* System */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

/* Libowfat */
#include "byte.h"
#include "scan.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_accesslist.h"

/* GLOBAL VARIABLES */
#ifdef WANT_ACCESS_CONTROL
static char *accesslist_filename = NULL;
static ot_vector accesslist;

static void accesslist_reset( void ) {
  free( accesslist.data );
  byte_zero( &accesslist, sizeof( accesslist ) );
}

static int accesslist_addentry( ot_hash *infohash ) {
  int eger;
  void *insert = vector_find_or_insert( &accesslist, infohash, OT_HASH_COMPARE_SIZE, OT_HASH_COMPARE_SIZE, &eger );

  if( !insert )
    return -1;

  memmove( insert, infohash, OT_HASH_COMPARE_SIZE );

  return 0;
}

/* Read initial access list */
static void accesslist_readfile( int foo ) {
  FILE *  accesslist_filehandle;
  ot_hash infohash;
  char    inbuf[512];
  foo = foo;

  accesslist_filehandle = fopen( accesslist_filename, "r" );

  /* Free accesslist vector in trackerlogic.c*/
  accesslist_reset();

  if( accesslist_filehandle == NULL ) {
    fprintf( stderr, "Warning: Can't open accesslist file: %s (but will try to create it later, if necessary and possible).", accesslist_filename );
    return;
  }

  /* We do ignore anything that is not of the form "^[:xdigit:]{40}[^:xdigit:].*" */
  while( fgets( inbuf, sizeof(inbuf), accesslist_filehandle ) ) {
    int i;
    for( i=0; i<20; ++i ) {
      int eger = 16 * scan_fromhex( inbuf[ 2*i ] ) + scan_fromhex( inbuf[ 1 + 2*i ] );
      if( eger < 0 )
        continue;
      infohash[i] = eger;
    }
    if( scan_fromhex( inbuf[ 40 ] ) >= 0 )
      continue;

    /* Append accesslist to accesslist vector */
    accesslist_addentry( &infohash );
  }

  fclose( accesslist_filehandle );
}

int accesslist_hashisvalid( ot_hash *hash ) {
  int exactmatch;
  binary_search( hash, accesslist.data, accesslist.size, OT_HASH_COMPARE_SIZE, OT_HASH_COMPARE_SIZE, &exactmatch );

#ifdef WANT_BLACKLISTING
  exactmatch = !exactmatch;
#endif

  return exactmatch;
}

void accesslist_init( char *accesslist_filename_in ) {
  byte_zero( &accesslist, sizeof( accesslist ) );

  /* Passing "0" since read_blacklist_file also is SIGHUP handler */
  if( accesslist_filename_in ) {
    accesslist_filename = accesslist_filename_in;
    accesslist_readfile( 0 );
    signal( SIGHUP,  accesslist_readfile );
  }
}

#endif

static uint32_t       g_adminip_addresses[OT_ADMINIP_MAX];
static ot_permissions g_adminip_permissions[OT_ADMINIP_MAX];
static unsigned int   g_adminip_count = 0;

int accesslist_blessip( char *ip, ot_permissions permissions ) {
  if( g_adminip_count >= OT_ADMINIP_MAX )
    return -1;
  memmove( g_adminip_addresses + g_adminip_count, ip, 4 );
  g_adminip_permissions[ g_adminip_count++ ] = permissions;
  return 0;
}

int accesslist_isblessed( char *ip, ot_permissions permissions ) {
  unsigned int i;
  for( i=0; i<g_adminip_count; ++i )
    if( !memcmp( g_adminip_addresses + i, ip, 4) && ( g_adminip_permissions[ i ] & permissions ) )
      return 1;
  return 0;
}
