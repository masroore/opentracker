/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <pthread.h>
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
static pthread_mutex_t g_accesslist_mutex;

static int vector_compare_hash(const void *hash1, const void *hash2 ) {
  return memcmp( hash1, hash2, OT_HASH_COMPARE_SIZE );
}

/* Read initial access list */
static void accesslist_readfile( void ) {
  ot_hash *info_hash, *accesslist_new = NULL;
  char    *map, *map_end, *read_offs;
  size_t   maplen;

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
  while( read_offs <= map_end ) {
    int i;
    for( i=0; i<(int)sizeof(ot_hash); ++i ) {
      int eger1 = scan_fromhex( read_offs[ 2*i ] );
      int eger2 = scan_fromhex( read_offs[ 1 + 2*i ] );
      if( eger1 < 0 || eger2 < 0 )
        break;
      (*info_hash)[i] = eger1 * 16 + eger2;
    }

    if( i == sizeof(ot_hash) ) {
      read_offs += 40;

      /* Append accesslist to accesslist vector */
      if( read_offs == map_end || scan_fromhex( *read_offs ) < 0 )
        ++info_hash;
    }

    /* Find start of next line */
    while( read_offs <= map_end && *(read_offs++) != '\n' );
  }
#ifdef _DEBUG
  fprintf( stderr, "Added %zd info_hashes to accesslist\n", (size_t)(info_hash - accesslist_new) );
#endif

  mmap_unmap( map, maplen);

  qsort( accesslist_new, info_hash - accesslist_new, sizeof( *info_hash ), vector_compare_hash );

  /* Now exchange the accesslist vector in the least race condition prone way */
  pthread_mutex_lock(&g_accesslist_mutex);
  free( g_accesslist );
  g_accesslist      = accesslist_new;
  g_accesslist_size = info_hash - accesslist_new;
  pthread_mutex_unlock(&g_accesslist_mutex);
}

int accesslist_hashisvalid( ot_hash hash ) {
  void *exactmatch;

  /* Lock should hardly ever be contended */
  pthread_mutex_lock(&g_accesslist_mutex);
  exactmatch = bsearch( hash, g_accesslist, g_accesslist_size, OT_HASH_COMPARE_SIZE, vector_compare_hash );
  pthread_mutex_unlock(&g_accesslist_mutex);

#ifdef WANT_ACCESSLIST_BLACK
  return exactmatch == NULL;
#else
  return exactmatch != NULL;
#endif
}

static void * accesslist_worker( void * args ) {
  int sig;
  sigset_t   signal_mask;

  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGHUP);

  (void)args;

  while( 1 ) {

    /* Initial attempt to read accesslist */
    accesslist_readfile( );

    /* Wait for signals */
    while( sigwait (&signal_mask, &sig) != 0 && sig != SIGHUP );
  }
  return NULL;
}

static pthread_t thread_id;
void accesslist_init( ) {
  pthread_mutex_init(&g_accesslist_mutex, NULL);
  pthread_create( &thread_id, NULL, accesslist_worker, NULL );
}

void accesslist_deinit( void ) {
  pthread_cancel( thread_id );
  pthread_mutex_destroy(&g_accesslist_mutex);
  free( g_accesslist );
  g_accesslist = 0;
  g_accesslist_size = 0;
}
#endif

int address_in_net( const ot_ip6 address, const ot_net *net ) {
  int bits = net->bits;
  int result = memcmp( address, &net->address, bits >> 3 );
  if( !result && ( bits & 7 ) )
    result = ( ( 0x7f00 >> ( bits & 7 ) ) & address[bits>>3] ) - net->address[bits>>3];
  return result == 0;
}

void *set_value_for_net( const ot_net *net, ot_vector *vector, const void *value, const size_t member_size ) {
  size_t i;
  int exactmatch;

  /* Caller must have a concept of ot_net in it's member */
  if( member_size < sizeof(ot_net) )
    return 0;

  /* Check each net in vector for overlap */
  uint8_t *member = ((uint8_t*)vector->data);
  for( i=0; i<vector->size; ++i ) {
    if( address_in_net( *(ot_ip6*)member, net ) ||
        address_in_net( net->address, (ot_net*)member ) )
      return 0;
    member += member_size;
  }

  member = vector_find_or_insert( vector, (void*)net, member_size, sizeof(ot_net), &exactmatch );
  if( member ) {
    memcpy( member, net, sizeof(ot_net));
    memcpy( member + sizeof(ot_net), value, member_size - sizeof(ot_net));
  }

  return member;
}

/* Takes a vector filled with { ot_net net, uint8_t[x] value };
   Returns value associated with the net, or NULL if not found */
void *get_value_for_net( const ot_ip6 address, const ot_vector *vector, const size_t member_size ) {
  int exactmatch;
  /* This binary search will return a pointer to the first non-containing network... */
  ot_net *net = binary_search( address, vector->data, vector->size, member_size, sizeof(ot_ip6), &exactmatch );
  if( !net )
    return NULL;
  /* ... so we'll need to move back one step unless we've exactly hit the first address in network */
  if( !exactmatch && ( (void*)net > vector->data ) )
    --net;
  if( !address_in_net( address, net ) )
    return NULL;
  return (void*)net;
}

#ifdef WANT_FULLLOG_NETWORKS
static ot_vector g_lognets_list;
ot_log *g_logchain_first, *g_logchain_last;

static pthread_mutex_t g_lognets_list_mutex = PTHREAD_MUTEX_INITIALIZER;
void loglist_add_network( const ot_net *net ) {
  pthread_mutex_lock(&g_lognets_list_mutex);
  set_value_for_net( net, &g_lognets_list, NULL, sizeof(ot_net));
  pthread_mutex_unlock(&g_lognets_list_mutex);
}

void loglist_reset( ) {
  pthread_mutex_lock(&g_lognets_list_mutex);
  free( g_lognets_list.data );
  g_lognets_list.data = 0;
  g_lognets_list.size = g_lognets_list.space = 0;
  pthread_mutex_unlock(&g_lognets_list_mutex);    
}

int loglist_check_address( const ot_ip6 address ) {
  int result;
  pthread_mutex_lock(&g_lognets_list_mutex);
  result = ( NULL != get_value_for_net( address, &g_lognets_list, sizeof(ot_net)) );
  pthread_mutex_unlock(&g_lognets_list_mutex);
  return result;
}
#endif

#ifdef WANT_IP_FROM_PROXY
typedef struct {
  ot_net    *proxy;
  ot_vector  networks;
} ot_proxymap;

static ot_vector g_proxies_list;
static pthread_mutex_t g_proxies_list_mutex = PTHREAD_MUTEX_INITIALIZER;

int proxylist_add_network( const ot_net *proxy, const ot_net *net ) {
  ot_proxymap *map;
  int exactmatch, result = 1;
  pthread_mutex_lock(&g_proxies_list_mutex);

  /* If we have a direct hit, use and extend the vector there */
  map = binary_search( proxy, g_proxies_list.data, g_proxies_list.size, sizeof(ot_proxymap), sizeof(ot_net), &exactmatch );

  if( !map || !exactmatch ) {
    /* else see, if we've got overlapping networks
       and get a new empty vector if not */
    ot_vector empty;
    memset( &empty, 0, sizeof( ot_vector ) );
    map = set_value_for_net( proxy, &g_proxies_list, &empty, sizeof(ot_proxymap));
  }

  if( map && set_value_for_net( net, &map->networks, NULL, sizeof(ot_net) ) )
       result = 1;

  pthread_mutex_unlock(&g_proxies_list_mutex);
  return result;
}

int proxylist_check_proxy( const ot_ip6 proxy, const ot_ip6 address ) {
  int result = 0;
  ot_proxymap *map;

  pthread_mutex_lock(&g_proxies_list_mutex);

  if( ( map = get_value_for_net( proxy, &g_proxies_list, sizeof(ot_proxymap) ) ) )
    if( !address || get_value_for_net( address, &map->networks, sizeof(ot_net) ) ) 
      result = 1;

  pthread_mutex_unlock(&g_proxies_list_mutex);
  return result;
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
