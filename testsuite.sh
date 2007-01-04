#!/bin/sh

while true; do
  request_string="GET /announce?info_hash=012345678901234567%$(printf %02X `jot -r 1 0 255`)%$(printf %02X `jot -r 1 0 255`)&\
ip=10.1.1.`jot -r 1 0 255`&\
port=`jot -r 1 0 255` HTTP/1.0\n"

  echo -e $request_string
  echo
  echo -e $request_string | nc erdgeist.org 6969 | tr -C "[:print:]" _
  echo

done
