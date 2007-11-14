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
  OT_TASKTYPE_FULLSCRAPE,
  OT_TASKTYPE_SYNC,
  OT_TASKTYPE_DMEM,

  OT_TASKTYPE_DONE
} ot_tasktype;
typedef unsigned long ot_taskid;

int       mutex_workqueue_pushtask( int64 socket, ot_tasktype tasktype );
void      mutex_workqueue_canceltask( int64 socket );
ot_taskid mutex_workqueue_poptask( ot_tasktype tasktype );
int       mutex_workqueue_pushresult( ot_taskid taskid, int iovec_entries, struct iovec *iovector );
int64     mutex_workqueue_popresult( int *iovec_entries, struct iovec ** iovector );

#endif
