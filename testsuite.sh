#!/bin/sh

while true; do
  request_string="GET /announce?info_hash=0123456789012345678%$(printf %02X $(( $RANDOM & 0xff )) )&\
ip=10.1.1.$(( $RANDOM & 0xff ))&port=$(( $RANDOM & 0xff )) HTTP/1.0\n"

#  echo -e $request_string
#  echo
  echo -e $request_string | nc 127.0.0.1 6969 >/dev/null
#  echo

done
