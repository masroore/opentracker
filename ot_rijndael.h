/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.

   The rijndael implementation was taken from

     http://www.cs.ucdavis.edu/~rogaway/ocb/ocb-ref/rijndael-alg-fst.c

   and modified to work with 128 bits (this is 10 rounds) only.

   $id$ */

#ifndef __OT_RIJNDAEL_H__
#define __OT_RIJNDAEL_H__

#include <stdint.h>

int rijndaelKeySetupEnc128(uint32_t rk[44], const uint8_t cipherKey[] );
void rijndaelEncrypt128(const uint32_t rk[44], const uint8_t pt[16], uint8_t ct[16]);

#endif
