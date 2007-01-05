#!/bin/sh

while true; do
  request_string="GET /announce?info_hash=0123456789012345678%$(printf %02X $(( $RANDOM & 0xff )) )&\
ip=10.1.1.$(( $RANDOM & 0xff ))&port=$(( $RANDOM & 0xff )) HTTP/1.0\n"

  echo -e $request_string
  echo
  echo -e $request_string | nc 213.73.88.214 6969 | tr -C "[:print:]" _
  echo

done
