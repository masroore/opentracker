/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
 It is considered beerware. Prost. Skol. Cheers or whatever.

 $id$ */

#ifndef __OT_LIVESYNC_H__
#define __OT_LIVESYNC_H__

#include "io.h"
#include "trackerlogic.h"

/*
  Syncing is done as udp packets in the multicast domain 224.0.42.N port 9696

  Each tracker should join the multicast group and send its live sync packets
  to that group, using a ttl of 1

  Format of a live sync packet is straight forward and depends on N:

  For N == 23: (simple tracker2tracker sync)
    0x0000 0x04 id of tracker instance
  [ 0x0004 0x14 info_hash
    0x0018 0x04 peer's ipv4 address
    0x001c 0x02 peer's port
    0x0020 0x02 peer flags v1 ( SEEDING = 0x80, COMPLETE = 0x40, STOPPED = 0x20 )
  ]*

  For N == 24: (aggregator syncs)
    0x0000 0x04 id of tracker instance
  [ 0x0004 0x14 info_hash
    0x0018 0x01 number of peers
    [ 0x0019 0x04 peer's ipv4 address
      0x001a 0x02 peer's port
      0x0021 0x02 peer flags v1 ( SEEDING = 0x80, COMPLETE = 0x40, STOPPED = 0x20 )
    ]+
  ]*


 */

#ifdef WANT_SYNC_LIVE

#define LIVESYNC_PORT 9696

void livesync_init();
void livesync_deinit();

/* Join multicast group for listening and create sending socket */
void livesync_bind_mcast( char *ip, uint16_t port );

/* Inform live sync about whats going on. */
void livesync_tell( ot_hash * const info_hash, const ot_peer * const peer, const uint8_t peerflag );

/* Tickle the live sync module from time to time, so no events get
   stuck when there's not enough traffic to fill udp packets fast
   enough */
void livesync_ticker( );

/* Handle an incoming live sync packet */
void handle_livesync( const int64 serversocket );

#else

/* If no syncing is required, save calling code from #ifdef
   constructions */

#define livesync_init()
#define livesync_ticker()
#define handle_livesync(a)

#endif

#endif
