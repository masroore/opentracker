#!/bin/sh

while true; do
  request_string="GET /announce?info_hash=0123456789012345678\
%$(printf %02X $(( $RANDOM & 0xf )) )\
&ip=$(( $RANDOM & 0xf )).$(( $RANDOM & 0xf )).13.16&port=$(( $RANDOM & 0xff )) HTTP/1.0\n"

echo $request_string
#  echo
  echo $request_string | nc 127.0.0.1 6969 >/dev/null
#  echo

done
