/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   $id$ */

#ifndef __OT_HTTP_H__
#define __OT_HTTP_H__

typedef enum {
  STRUCT_HTTP_FLAG_ARRAY_USED     = 1,
  STRUCT_HTTP_FLAG_IOB_USED       = 2,
  STRUCT_HTTP_FLAG_WAITINGFORTASK = 4,
  STRUCT_HTTP_FLAG_GZIP           = 8,
  STRUCT_HTTP_FLAG_BZIP2          = 16
} STRUCT_HTTP_FLAG;

struct http_data {
  union {
    array          request;
    io_batch       batch;
  } data;
  ot_ip6           ip;
  STRUCT_HTTP_FLAG flag;
};

ssize_t http_handle_request( const int64 s, struct ot_workstruct *ws );
ssize_t http_sendiovecdata( const int64 s, struct ot_workstruct *ws, int iovec_entries, struct iovec *iovector );
ssize_t http_issue_error( const int64 s, struct ot_workstruct *ws, int code );

#endif
