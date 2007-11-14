/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

/* System */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

/* Libowfat */
#include "byte.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"

/* Our global all torrents list */
static ot_vector all_torrents[OT_BUCKET_COUNT];

/* Bucket Magic */
static int bucket_locklist[ OT_MAX_THREADS ];
static int bucket_locklist_count = 0;
static pthread_mutex_t bucket_mutex;
static pthread_cond_t bucket_being_unlocked;

static int bucket_check( int bucket ) {
  /* C should come with auto-i ;) */
  int i;

  /* No more space to acquire lock to bucket -- should not happen */
  if( bucket_locklist_count == OT_MAX_THREADS ) {
    fprintf( stderr, "More lock requests than mutexes. Consult source code.\n" );
    return -1;
  }

  /* See, if bucket is already locked */
  for( i=0; i<bucket_locklist_count; ++i )
    if( bucket_locklist[ i ] == bucket )
      return -1;

  return 0;
}

static void bucket_push( int bucket ) {
  bucket_locklist[ bucket_locklist_count++ ] = bucket;
}

static void bucket_remove( int bucket ) {
  int i = 0;

  while( ( i < bucket_locklist_count ) && ( bucket_locklist[ i ] != bucket ) )
    ++i;

  if( i == bucket_locklist_count ) {
    fprintf( stderr, "Request to unlock bucket that was never lock. Consult source code.\n" );
    return;
  }

  for( ; i < bucket_locklist_count - 1; ++i )
    bucket_locklist[ i ] = bucket_locklist[ i + 1 ];

  --bucket_locklist_count;
}

ot_vector *mutex_bucket_lock( int bucket ) {
  pthread_mutex_lock( &bucket_mutex );
  while( bucket_check( bucket ) )
    pthread_cond_wait( &bucket_being_unlocked, &bucket_mutex );
  bucket_push( bucket );
  pthread_mutex_unlock( &bucket_mutex );
  return all_torrents + bucket;
}

ot_vector *mutex_bucket_lock_by_hash( ot_hash *hash ) {
  unsigned char *local_hash = hash[0];
  int bucket = ( local_hash[0] << 2 ) | ( local_hash[1] >> 6 );

  /* Can block */
  mutex_bucket_lock( bucket );

  return all_torrents + bucket;
}

void mutex_bucket_unlock( int bucket ) {
  pthread_mutex_lock( &bucket_mutex );
  bucket_remove( bucket );
  pthread_cond_broadcast( &bucket_being_unlocked );
  pthread_mutex_unlock( &bucket_mutex );
}   

void mutex_bucket_unlock_by_hash( ot_hash *hash ) {
  unsigned char *local_hash = hash[0];
  int bucket = ( local_hash[0] << 2 ) | ( local_hash[1] >> 6 );
  mutex_bucket_unlock( bucket );
}

/* TaskQueue Magic */

struct ot_task {
  ot_taskid       taskid;
  ot_tasktype     tasktype;
  int64           socket;
  int             iovec_entries;
  struct iovec   *iovec;
  struct ot_task *next;
};

static ot_taskid next_free_taskid = 1;
static struct ot_task *tasklist = NULL;
static pthread_mutex_t tasklist_mutex;
static pthread_cond_t tasklist_being_filled;

int mutex_workqueue_pushtask( int64 socket, ot_tasktype tasktype ) {
  struct ot_task ** tmptask, * task;

  /* Want exclusive access to tasklist */
  pthread_mutex_lock( &tasklist_mutex );

  task = malloc(sizeof( struct ot_task));
  if( !task ) {
    pthread_mutex_unlock( &tasklist_mutex );
    return -1;
  }
    
  /* Skip to end of list */
  tmptask = &tasklist; 
  while( *tmptask )
    tmptask = &(*tmptask)->next;
  *tmptask = task;

  task->taskid        = 0;
  task->tasktype      = tasktype;
  task->socket        = socket;
  task->iovec_entries = 0;
  task->iovec         = NULL;
  task->next          = 0;

  /* Inform waiting workers and release lock */
  pthread_cond_broadcast( &tasklist_being_filled );
  pthread_mutex_unlock( &tasklist_mutex );
  return 0;
}

void mutex_workqueue_canceltask( int64 socket ) {
  struct ot_task ** task;

  /* Want exclusive access to tasklist */
  pthread_mutex_lock( &tasklist_mutex );

  task = &tasklist;
  while( *task && ( (*task)->socket != socket ) )
    *task = (*task)->next;

  if( *task && ( (*task)->socket == socket ) ) {
    struct iovec *iovec = (*task)->iovec;
    struct ot_task *ptask = *task;
    int i;

    /* Free task's iovec */
    for( i=0; i<(*task)->iovec_entries; ++i )
      munmap( iovec[i].iov_base , iovec[i].iov_len );

    *task = (*task)->next;
    free( ptask );
  }

  /* Release lock */
  pthread_mutex_unlock( &tasklist_mutex );
}

ot_taskid mutex_workqueue_poptask( ot_tasktype tasktype ) {
  struct ot_task * task;
  ot_taskid taskid = 0;

  /* Want exclusive access to tasklist */
  pthread_mutex_lock( &tasklist_mutex );

  while( !taskid ) {
    /* Skip to the first unassigned task this worker wants to do */
    task = tasklist;
    while( task && ( task->tasktype != tasktype ) && ( task->taskid ) )
      task = task->next;

    /* If we found an outstanding task, assign a taskid to it
       and leave the loop */
    if( task ) {
      task->taskid = taskid = ++next_free_taskid;
      break;
    }

    /* Wait until the next task is being fed */
    pthread_cond_wait( &tasklist_being_filled, &tasklist_mutex );
  }

  /* Release lock */
  pthread_mutex_unlock( &tasklist_mutex );

  return taskid;
}

int mutex_workqueue_pushresult( ot_taskid taskid, int iovec_entries, struct iovec *iovec ) {
  struct ot_task * task;
  /* Want exclusive access to tasklist */
  pthread_mutex_lock( &tasklist_mutex );

  task = tasklist;
  while( task && ( task->taskid != taskid ) )
    task = task->next;

  if( task ) {
    task->iovec_entries = iovec_entries;
    task->iovec         = iovec;
    task->tasktype      = OT_TASKTYPE_DONE;
  }

  /* Release lock */
  pthread_mutex_unlock( &tasklist_mutex );
  
  /* Indicate whether the worker has to throw away results */
  return task ? 0 : -1;
}

int64 mutex_workqueue_popresult( int *iovec_entries, struct iovec ** iovec ) {
  struct ot_task ** task;
  int64 socket = -1;

  /* Want exclusive access to tasklist */
  pthread_mutex_lock( &tasklist_mutex );

  task = &tasklist;
  while( *task && ( (*task)->tasktype != OT_TASKTYPE_DONE ) )
    *task = (*task)->next;

  if( *task && ( (*task)->tasktype == OT_TASKTYPE_DONE ) ) {
    struct ot_task *ptask = *task;

    *iovec_entries = (*task)->iovec_entries;
    *iovec         = (*task)->iovec;
    socket         = (*task)->socket;
    
    *task = (*task)->next;
    free( ptask );
  }

  /* Release lock */
  pthread_mutex_unlock( &tasklist_mutex );
  return socket;
}

void mutex_init( ) {
  pthread_mutex_init(&bucket_mutex, NULL);
  pthread_cond_init (&bucket_being_unlocked, NULL);
  byte_zero( all_torrents, sizeof( all_torrents ) );
}

void mutex_deinit( ) {
  pthread_mutex_destroy(&bucket_mutex);
  pthread_cond_destroy(&bucket_being_unlocked);
  byte_zero( all_torrents, sizeof( all_torrents ) );
}
