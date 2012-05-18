/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifndef __OT_MUTEX_H__
#define __OT_MUTEX_H__

#include <sys/uio.h>

void mutex_init( );
void mutex_deinit( );

ot_vector *mutex_bucket_lock( int bucket );
ot_vector *mutex_bucket_lock_by_hash( ot_hash hash );

void mutex_bucket_unlock( int bucket, int delta_torrentcount );
void mutex_bucket_unlock_by_hash( ot_hash hash, int delta_torrentcount );

size_t mutex_get_torrent_count();

typedef enum {
  TASK_STATS_CONNS                 = 0x0001,
  TASK_STATS_TCP                   = 0x0002,
  TASK_STATS_UDP                   = 0x0003,
  TASK_STATS_SCRAPE                = 0x0004,
  TASK_STATS_FULLSCRAPE            = 0x0005,
  TASK_STATS_TPB                   = 0x0006,
  TASK_STATS_HTTPERRORS            = 0x0007,
  TASK_STATS_VERSION               = 0x0008,
  TASK_STATS_BUSY_NETWORKS         = 0x0009,
  TASK_STATS_RENEW                 = 0x000a,
  TASK_STATS_SYNCS                 = 0x000b,
  TASK_STATS_COMPLETED             = 0x000c,
  TASK_STATS_NUMWANTS              = 0x000d,

  TASK_STATS                       = 0x0100, /* Mask */
  TASK_STATS_TORRENTS              = 0x0101,
  TASK_STATS_PEERS                 = 0x0102,
  TASK_STATS_SLASH24S              = 0x0103,
  TASK_STATS_TOP10                 = 0x0104,
  TASK_STATS_TOP100                = 0x0105,
  TASK_STATS_EVERYTHING            = 0x0106,
  TASK_STATS_FULLLOG               = 0x0107,
  TASK_STATS_WOODPECKERS           = 0x0108,
  
  TASK_FULLSCRAPE                  = 0x0200, /* Default mode */
  TASK_FULLSCRAPE_TPB_BINARY       = 0x0201,
  TASK_FULLSCRAPE_TPB_ASCII        = 0x0202,
  TASK_FULLSCRAPE_TPB_URLENCODED   = 0x0203,
  TASK_FULLSCRAPE_TRACKERSTATE     = 0x0204,

  TASK_DMEM                        = 0x0300,

  TASK_DONE                        = 0x0f00,

  TASK_FLAG_GZIP                   = 0x1000,
  TASK_FLAG_BZIP2                  = 0x2000,

  TASK_TASK_MASK                   = 0x0fff,
  TASK_CLASS_MASK                  = 0x0f00,
  TASK_FLAGS_MASK                  = 0xf000
} ot_tasktype;

typedef unsigned long ot_taskid;

int       mutex_workqueue_pushtask( int64 sock, ot_tasktype tasktype );
void      mutex_workqueue_canceltask( int64 sock );
void      mutex_workqueue_pushsuccess( ot_taskid taskid );
ot_taskid mutex_workqueue_poptask( ot_tasktype *tasktype );
int       mutex_workqueue_pushresult( ot_taskid taskid, int iovec_entries, struct iovec *iovector );
int64     mutex_workqueue_popresult( int *iovec_entries, struct iovec ** iovector );

#endif
