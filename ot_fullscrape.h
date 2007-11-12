/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __OT_FULLSCRAPE_H__
#define __OT_FULLSCRAPE_H__

#include <sys/uio.h>

size_t return_fullscrape_for_tracker( int *iovec_entries, struct iovec **iovector );

#endif