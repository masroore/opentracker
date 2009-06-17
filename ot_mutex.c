/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

/* System */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/uio.h>

/* Libowfat */
#include "byte.h"
#include "io.h"
#include "uint32.h"

/* Opentracker */
#include "trackerlogic.h"
#include "ot_mutex.h"
#include "ot_stats.h"

/* #define MTX_DBG( STRING ) fprintf( stderr, STRING ) */
#define MTX_DBG( STRING )

/* Our global all torrents list */
static ot_vector all_torrents[OT_BUCKET_COUNT];
static size_t    g_torrent_count;

/* Bucket Magic */
static int bucket_locklist[ OT_MAX_THREADS ];
static int bucket_locklist_count = 0;
static pthread_mutex_t bucket_mutex;
static pthread_cond_t bucket_being_unlocked;

/* Self pipe from opentracker.c */
extern int g_self_pipe[2];

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
    if( bucket_locklist[ i ] == bucket ) {
      stats_issue_event( EVENT_BUCKET_LOCKED, 0, 0 );
      return -1;
    }

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
    fprintf( stderr, "Request to unlock bucket that was never locked. Consult source code.\n" );
    return;
  }

  for( ; i < bucket_locklist_count - 1; ++i )
    bucket_locklist[ i ] = bucket_locklist[ i + 1 ];

  --bucket_locklist_count;
}

/* Can block */
ot_vector *mutex_bucket_lock( int bucket ) {
  pthread_mutex_lock( &bucket_mutex );
  while( bucket_check( bucket ) )
    pthread_cond_wait( &bucket_being_unlocked, &bucket_mutex );
  bucket_push( bucket );
  pthread_mutex_unlock( &bucket_mutex );
  return all_torrents + bucket;
}

ot_vector *mutex_bucket_lock_by_hash( ot_hash hash ) {
  return mutex_bucket_lock( uint32_read_big( (char*)hash ) >> OT_BUCKET_COUNT_SHIFT );
}

void mutex_bucket_unlock( int bucket, int delta_torrentcount ) {
  pthread_mutex_lock( &bucket_mutex );
  bucket_remove( bucket );
  g_torrent_count += delta_torrentcount;
  pthread_cond_broadcast( &bucket_being_unlocked );
  pthread_mutex_unlock( &bucket_mutex );
}

void mutex_bucket_unlock_by_hash( ot_hash hash, int delta_torrentcount ) {
  mutex_bucket_unlock( uint32_read_big( (char*)hash ) >> OT_BUCKET_COUNT_SHIFT, delta_torrentcount );
}

size_t mutex_get_torrent_count( ) {
  size_t torrent_count;
  pthread_mutex_lock( &bucket_mutex );
  torrent_count = g_torrent_count;
  pthread_mutex_unlock( &bucket_mutex );
  return torrent_count;
}

/* TaskQueue Magic */

struct ot_task {
  ot_taskid       taskid;
  ot_tasktype     tasktype;
  int64           sock;
  int             iovec_entries;
  struct iovec   *iovec;
  struct ot_task *next;
};

static ot_taskid next_free_taskid = 1;
static struct ot_task *tasklist;
static pthread_mutex_t tasklist_mutex;
static pthread_cond_t tasklist_being_filled;

int mutex_workqueue_pushtask( int64 sock, ot_tasktype tasktype ) {
  struct ot_task ** tmptask, * task;

  /* Want exclusive access to tasklist */
  MTX_DBG( "pushtask locks.\n" );
  pthread_mutex_lock( &tasklist_mutex );
  MTX_DBG( "pushtask locked.\n" );

  task = malloc(sizeof( struct ot_task));
  if( !task ) {
    MTX_DBG( "pushtask fail unlocks.\n" );
    pthread_mutex_unlock( &tasklist_mutex );
    MTX_DBG( "pushtask fail unlocked.\n" );
    return -1;
  }

  /* Skip to end of list */
  tmptask = &tasklist;
  while( *tmptask )
    tmptask = &(*tmptask)->next;
  *tmptask = task;

  task->taskid        = 0;
  task->tasktype      = tasktype;
  task->sock          = sock;
  task->iovec_entries = 0;
  task->iovec         = NULL;
  task->next          = 0;

  /* Inform waiting workers and release lock */
  MTX_DBG( "pushtask broadcasts.\n" );
  pthread_cond_broadcast( &tasklist_being_filled );
  MTX_DBG( "pushtask broadcasted, mutex unlocks.\n" );
  pthread_mutex_unlock( &tasklist_mutex );
  MTX_DBG( "pushtask end mutex unlocked.\n" );
  return 0;
}

void mutex_workqueue_canceltask( int64 sock ) {
  struct ot_task ** task;

  /* Want exclusive access to tasklist */
  MTX_DBG( "canceltask locks.\n" );
  pthread_mutex_lock( &tasklist_mutex );
  MTX_DBG( "canceltask locked.\n" );

  task = &tasklist;
  while( *task && ( (*task)->sock != sock ) )
    *task = (*task)->next;

  if( *task && ( (*task)->sock == sock ) ) {
    struct iovec *iovec = (*task)->iovec;
    struct ot_task *ptask = *task;
    int i;

    /* Free task's iovec */
    for( i=0; i<(*task)->iovec_entries; ++i )
      munmap( iovec[i].iov_base, iovec[i].iov_len );

    *task = (*task)->next;
    free( ptask );
  }

  /* Release lock */
  MTX_DBG( "canceltask unlocks.\n" );
  pthread_mutex_unlock( &tasklist_mutex );
  MTX_DBG( "canceltask unlocked.\n" );
}

ot_taskid mutex_workqueue_poptask( ot_tasktype *tasktype ) {
  struct ot_task * task;
  ot_taskid taskid = 0;

  /* Want exclusive access to tasklist */
  MTX_DBG( "poptask mutex locks.\n" );
  pthread_mutex_lock( &tasklist_mutex );
  MTX_DBG( "poptask mutex locked.\n" );

  while( !taskid ) {
    /* Skip to the first unassigned task this worker wants to do */
    task = tasklist;
    while( task && ( ( ( TASK_CLASS_MASK & task->tasktype ) != *tasktype ) || task->taskid ) )
      task = task->next;

    /* If we found an outstanding task, assign a taskid to it
       and leave the loop */
    if( task ) {
      task->taskid = taskid = ++next_free_taskid;
      *tasktype = task->tasktype;
    } else {
      /* Wait until the next task is being fed */
      MTX_DBG( "poptask cond waits.\n" );
      pthread_cond_wait( &tasklist_being_filled, &tasklist_mutex );
      MTX_DBG( "poptask cond waited.\n" );
    }
  }

  /* Release lock */
  MTX_DBG( "poptask end mutex unlocks.\n" );
  pthread_mutex_unlock( &tasklist_mutex );
  MTX_DBG( "poptask end mutex unlocked.\n" );

  return taskid;
}

void mutex_workqueue_pushsuccess( ot_taskid taskid ) {
  struct ot_task ** task;

  /* Want exclusive access to tasklist */
  MTX_DBG( "pushsuccess locks.\n" );
  pthread_mutex_lock( &tasklist_mutex );
  MTX_DBG( "pushsuccess locked.\n" );

  task = &tasklist;
  while( *task && ( (*task)->taskid != taskid ) )
    *task = (*task)->next;

  if( *task && ( (*task)->taskid == taskid ) ) {
    struct ot_task *ptask = *task;
    *task = (*task)->next;
    free( ptask );
  }

  /* Release lock */
  MTX_DBG( "pushsuccess unlocks.\n" );
  pthread_mutex_unlock( &tasklist_mutex );
  MTX_DBG( "pushsuccess unlocked.\n" );
}

int mutex_workqueue_pushresult( ot_taskid taskid, int iovec_entries, struct iovec *iovec ) {
  struct ot_task * task;
  const char byte = 'o';

  /* Want exclusive access to tasklist */
  MTX_DBG( "pushresult locks.\n" );
  pthread_mutex_lock( &tasklist_mutex );
  MTX_DBG( "pushresult locked.\n" );

  task = tasklist;
  while( task && ( task->taskid != taskid ) )
    task = task->next;

  if( task ) {
    task->iovec_entries = iovec_entries;
    task->iovec         = iovec;
    task->tasktype      = TASK_DONE;
  }

  /* Release lock */
  MTX_DBG( "pushresult unlocks.\n" );
  pthread_mutex_unlock( &tasklist_mutex );
  MTX_DBG( "pushresult unlocked.\n" );

  io_trywrite( g_self_pipe[1], &byte, 1 );

  /* Indicate whether the worker has to throw away results */
  return task ? 0 : -1;
}

int64 mutex_workqueue_popresult( int *iovec_entries, struct iovec ** iovec ) {
  struct ot_task ** task;
  int64 sock = -1;

  /* Want exclusive access to tasklist */
  MTX_DBG( "popresult locks.\n" );
  pthread_mutex_lock( &tasklist_mutex );
  MTX_DBG( "popresult locked.\n" );

  task = &tasklist;
  while( *task && ( (*task)->tasktype != TASK_DONE ) )
    task = &(*task)->next;

  if( *task && ( (*task)->tasktype == TASK_DONE ) ) {
    struct ot_task *ptask = *task;

    *iovec_entries = (*task)->iovec_entries;
    *iovec         = (*task)->iovec;
    sock           = (*task)->sock;

    *task = (*task)->next;
    free( ptask );
  }

  /* Release lock */
  MTX_DBG( "popresult unlocks.\n" );
  pthread_mutex_unlock( &tasklist_mutex );
  MTX_DBG( "popresult unlocked.\n" );
  return sock;
}

void mutex_init( ) {
  pthread_mutex_init(&tasklist_mutex, NULL);
  pthread_cond_init (&tasklist_being_filled, NULL);
  pthread_mutex_init(&bucket_mutex, NULL);
  pthread_cond_init (&bucket_being_unlocked, NULL);
  byte_zero( all_torrents, sizeof( all_torrents ) );
}

void mutex_deinit( ) {
  pthread_mutex_destroy(&bucket_mutex);
  pthread_cond_destroy(&bucket_being_unlocked);
  pthread_mutex_destroy(&tasklist_mutex);
  pthread_cond_destroy(&tasklist_being_filled);
  byte_zero( all_torrents, sizeof( all_torrents ) );
}

const char *g_version_mutex_c = "$Source$: $Revision$\n";
