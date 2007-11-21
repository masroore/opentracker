/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef __OT_MUTEX_H__
#define __OT_MUTEX_H__

#include "ot_iovec.h"
#include "io.h"

void mutex_init( );
void mutex_deinit( );

ot_vector *mutex_bucket_lock( int bucket );
ot_vector *mutex_bucket_lock_by_hash( ot_hash *hash );

void mutex_bucket_unlock( int bucket );
void mutex_bucket_unlock_by_hash( ot_hash *hash );

typedef enum {
  TASK_STATS_CONNS                 = 0x0000,
  TASK_STATS_PEERS                 = 0x0001,
  TASK_STATS_TOP5                  = 0x0002,
  TASK_STATS_TCP                   = 0x0003,
  TASK_STATS_UDP                   = 0x0004,
  TASK_STATS_FULLSCRAPE            = 0x0005,
  TASK_STATS_TPB                   = 0x0006,

  TASK_STATS_SLASH24S              = 0x0100,

  TASK_FULLSCRAPE                  = 0x0200, /* Default mode */
  TASK_FULLSCRAPE_TPB_BINARY       = 0x0201,
  TASK_FULLSCRAPE_TPB_ASCII        = 0x0202,
  TASK_FULLSCRAPE_TPB_URLENCODED   = 0x0203,

  TASK_CLEAN                       = 0x0300,

  TASK_SYNC_OUT                    = 0x0400,
  TASK_SYNC_IN                     = 0x0401,

  TASK_DMEM                        = 0x0500,

  TASK_DONE                        = 0x0f00,
  TASK_MASK                        = 0xff00
} ot_tasktype;

typedef unsigned long ot_taskid;

int       mutex_workqueue_pushtask( int64 socket, ot_tasktype tasktype );
void      mutex_workqueue_canceltask( int64 socket );
void      mutex_workqueue_pushsuccess( ot_taskid taskid );
ot_taskid mutex_workqueue_poptask( ot_tasktype *tasktype );
int       mutex_workqueue_pushresult( ot_taskid taskid, int iovec_entries, struct iovec *iovector );
int64     mutex_workqueue_popresult( int *iovec_entries, struct iovec ** iovector );

#endif
