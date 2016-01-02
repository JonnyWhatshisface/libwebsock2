/*
  utilities.h

    Jonathan D. Hall - jhall@futuresouth.us
    Copyright 2015 Future South Technologies

    This file is part of libwebsock2.

    libwebsock2 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libwebsock2 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libwebsock2.  If not, see <http://www.gnu.org/licenses/>.

*/

/*
 * SHA1 functions written by Paul E. Jones <paulej@packetizer.com>
 * Copyright (C) 1998, 2009 - All Rights Reserved
 */

#ifndef _utilities_h
#define _utilities_h

#include "core.h"
#include "websock.h"

typedef struct SHA1Context
{
    unsigned Message_Digest[5]; /* Message Digest (output)          */
    
    unsigned Length_Low;        /* Message length in bits           */
    unsigned Length_High;       /* Message length in bits           */
    
    unsigned char Message_Block[64]; /* 512-bit message blocks      */
    int Message_Block_Index;    /* Index into message block array   */
    
    int Computed;               /* Is the digest computed?          */
    int Corrupted;              /* Is the message digest corruped?  */
} SHA1Context;


/* UTF prototypes */

int validate_utf8_sequence(uint8_t *s);
uint16_t lws_htobe16(uint16_t x);
uint16_t lws_be16toh(uint16_t x);
uint64_t lws_htobe64(uint64_t x);
uint64_t lws_be64toh(uint64_t x);


/* Base64 prototypes */

int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen);
void _base64_encode_triple(unsigned char triple[3], char result[4]);
int _base64_char_value(char base64char);
int _base64_decode_triple(char quadruple[4], unsigned char *result);
size_t base64_decode(char *source, unsigned char *target, size_t targetlen);

/* SHA1 prototypes */

void SHA1Reset(SHA1Context *);
int SHA1Result(SHA1Context *);
void SHA1Input( SHA1Context *, const unsigned char *, unsigned);
void SHA1ProcessMessageBlock(SHA1Context *);
void SHA1PadMessage(SHA1Context *);

#endif /* utilities_h */
