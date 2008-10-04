#!/bin/sh

while true; do
  request_string="GET /announce?info_hash=012345678901234567\
%$(printf %02X $(( $RANDOM & 0xff )) )\
%$(printf %02X $(( $RANDOM & 0xff )) )\
&ip=$(( $RANDOM & 0xff )).17.13.15&port=$(( $RANDOM & 0xff )) HTTP/1.0\n"

  echo $request_string
  echo
  echo $request_string | nc 10.0.1.3 6969 >/dev/null
  echo

done
