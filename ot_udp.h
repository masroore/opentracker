/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifndef __OT_UDP_H__
#define __OT_UDP_H__

void udp_init( int64 sock, unsigned int worker_count );
int  handle_udp6( int64 serversocket, struct ot_workstruct *ws );

#endif
