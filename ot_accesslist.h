/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifndef __OT_ACCESSLIST_H__
#define __OT_ACCESSLIST_H__

#if defined ( WANT_ACCESSLIST_BLACK ) && defined (WANT_ACCESSLIST_WHITE )
#  error WANT_ACCESSLIST_BLACK and WANT_ACCESSLIST_WHITE are exclusive.
#endif

#if defined ( WANT_ACCESSLIST_BLACK ) || defined (WANT_ACCESSLIST_WHITE )
#define WANT_ACCESSLIST
void accesslist_init( );
void accesslist_deinit( );
int  accesslist_hashisvalid( ot_hash hash );

extern char *g_accesslist_filename;

#else
#define accesslist_init( accesslist_filename )
#define accesslist_deinit( )
#define accesslist_hashisvalid( hash ) 1
#endif

/* Test if an address is subset of an ot_net, return value is considered a bool */
int address_in_net( const ot_ip6 address, const ot_net *net );

/* Store a value into a vector of struct { ot_net net, uint8_t[x] value } member;
   returns NULL
     if member_size is too small, or
     if one of the nets inside the vector are a subnet of _net_, or
     if _net_ is a subnet of one of the nets inside the vector, or
     if the vector could not be resized
   returns pointer to new member in vector for success
   member_size can be sizeof(ot_net) to reduce the lookup to a boolean mapping
*/
void *set_value_for_net( const ot_net *net, ot_vector *vector, const void *value, const size_t member_size );

/* Takes a vector filled with struct { ot_net net, uint8_t[x] value } member;
   Returns pointer to _member_ associated with the net, or NULL if not found
   member_size can be sizeof(ot_net) to reduce the lookup to a boolean mapping
*/
void *get_value_for_net( const ot_ip6 address, const ot_vector *vector, const size_t member_size );


#ifdef WANT_IP_FROM_PROXY
int proxylist_add_network( const ot_net *proxy, const ot_net *net );
int proxylist_check_network( const ot_ip6 *proxy, const ot_ip6 address /* can be NULL to only check proxy */ );
#endif

#ifdef WANT_FULLLOG_NETWORKS
typedef struct ot_log ot_log;
struct ot_log {
  ot_ip6   ip;
  uint8_t *data;
  size_t   size;
  ot_time  time;
  ot_log  *next;
};
extern ot_log *g_logchain_first, *g_logchain_last;

void loglist_add_network( const ot_net *net );
void loglist_reset( );
int  loglist_check_address( const ot_ip6 address );
#endif  

typedef enum {
  OT_PERMISSION_MAY_FULLSCRAPE = 0x1,
  OT_PERMISSION_MAY_STAT       = 0x2,
  OT_PERMISSION_MAY_LIVESYNC   = 0x4,
  OT_PERMISSION_MAY_PROXY      = 0x8
} ot_permissions;

int  accesslist_blessip( ot_ip6 ip, ot_permissions permissions );
int  accesslist_isblessed( ot_ip6 ip, ot_permissions permissions );

#endif
