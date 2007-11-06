/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __OT_SYNC_H__
#define __OT_SYNC_H__

#include "trackerlogic.h"

#ifdef WANT_TRACKER_SYNC
size_t return_changeset_for_tracker( char **reply );
int    add_changeset_to_tracker( ot_byte *data, size_t len );
#endif

#endif
