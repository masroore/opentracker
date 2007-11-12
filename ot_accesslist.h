/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __OT_ACCESSLIST_H__
#define __OT_ACCESSLIST_H__

#include "trackerlogic.h"

#if defined ( WANT_BLACKLISTING ) && defined (WANT_CLOSED_TRACKER )
  #error WANT_BLACKLISTING and WANT_CLOSED_TRACKER are exclusive.
#endif

#if defined ( WANT_BLACKLISTING ) || defined (WANT_CLOSED_TRACKER )
#define WANT_ACCESS_CONTROL
void accesslist_init( char *accesslist_filename );
int  accesslist_hashisvalid( ot_hash *hash );
#else
#define accesslist_init( accesslist_filename )
#define accesslist_hashisvalid( hash ) 1
#endif

#endif
