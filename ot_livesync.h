/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
 It is considered beerware. Prost. Skol. Cheers or whatever.

 $id$ */

#ifndef __OT_LIVESYNC_H__
#define __OT_LIVESYNC_H__

#include "io.h"
#include "trackerlogic.h"

/*
  Syncing is done as udp packets in the multicast domain 224.0.42.5 port 9696

  Each tracker should join the multicast group and send its live sync packets
  to that group, using a ttl of 1

  Format of all sync packets is straight forward, packet type determines
  which kind of packet this is:

    0x0000 0x04 id of tracker instance
    0x0004 0x04 packet type

                             ########
 ######## PEER SYNC PROTOCOL ########
 ########

  Each tracker instance accumulates announce requests until its buffer is
  full or a timeout is reached. Then it broadcasts its live sync packer:

  packet type SYNC_LIVE
  [ 0x0008 0x14 info_hash
    0x001c 0x04 peer's ipv4 address
    0x0020 0x02 peer's port
    0x0024 0x02 peer flags v1 ( SEEDING = 0x80, COMPLETE = 0x40, STOPPED = 0x20 )
  ]*

*/

#ifdef WANT_SYNC_LIVE

#define LIVESYNC_PORT 9696

void livesync_init();
void livesync_deinit();

/* Join multicast group for listening and create sending socket */
void livesync_bind_mcast( char *ip, uint16_t port );

/* Inform live sync about whats going on. */
void livesync_tell( struct ot_workstruct *ws );

/* Tickle the live sync module from time to time, so no events get
   stuck when there's not enough traffic to fill udp packets fast
   enough */
void livesync_ticker( );

/* Handle an incoming live sync packet */
void handle_livesync( const int64 sock );

#else

/* If no syncing is required, save calling code from #ifdef
   constructions */
#define livesync_deinit()
#define livesync_init()
#define livesync_ticker()
#define handle_livesync(a)

#endif

#endif
