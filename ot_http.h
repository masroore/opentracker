/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifndef __OT_HTTP_H__
#define __OT_HTTP_H__

typedef enum {
  STRUCT_HTTP_FLAG_WAITINGFORTASK = 1,
  STRUCT_HTTP_FLAG_GZIP           = 2,
  STRUCT_HTTP_FLAG_BZIP2          = 4
} STRUCT_HTTP_FLAG;

struct http_data {
  array            request;
  io_batch         batch;
  ot_ip6           ip;
  STRUCT_HTTP_FLAG flag;
};

ssize_t http_handle_request( const int64 s, struct ot_workstruct *ws );
ssize_t http_sendiovecdata( const int64 s, struct ot_workstruct *ws, int iovec_entries, struct iovec *iovector );
ssize_t http_issue_error( const int64 s, struct ot_workstruct *ws, int code );

extern char   *g_stats_path;
extern ssize_t g_stats_path_len;

#endif
