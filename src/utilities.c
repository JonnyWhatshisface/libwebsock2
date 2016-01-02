/*
  utilities.c

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

#include "utilities.h"

#define UTF8_ACCEPT 0
#define UTF8_REJECT 1

#define SHA1CircularShift(bits,word) \
((((word) << (bits)) & 0xFFFFFFFF) | \
((word) >> (32-(bits))))

uint32_t inline decode(uint32_t *state, uint32_t *codep, uint32_t byte);

//these functions assume little endian machine as they're only used on windows
uint16_t lws_htobe16(uint16_t x)
{
    return ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8);
}

uint16_t lws_be16toh(uint16_t x)
{
    return ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8);
}

uint64_t lws_htobe64(uint64_t x)
{
    return (x >> 56) |
    ((x << 40) & 0x00ff000000000000LL) |
    ((x << 24) & 0x0000ff0000000000LL) |
    ((x << 8) & 0x000000ff00000000LL) |
    ((x >> 8) & 0x00000000ff000000LL) |
    ((x >> 24) & 0x0000000000ff0000LL) |
    ((x >> 40) & 0x000000000000ff00LL) |
    (x << 56);
}

uint64_t lws_be64toh(uint64_t x)
{
    return (x >> 56) |
    ((x << 40) & 0x00ff000000000000LL) |
    ((x << 24) & 0x0000ff0000000000LL) |
    ((x << 8) & 0x000000ff00000000LL) |
    ((x >> 8) & 0x00000000ff000000LL) |
    ((x >> 24) & 0x0000000000ff0000LL) |
    ((x >> 40) & 0x000000000000ff00LL) |
    (x << 56);
}

int validate_utf8_sequence(uint8_t *s)
{
    uint32_t codepoint;
    uint32_t state = 0;
    
    for(; *s; ++s) {
        decode(&state, &codepoint, *s);
    }
    
    return state == UTF8_ACCEPT;
}

const uint8_t utf8d[] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 00..1f
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 20..3f
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 40..5f
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 60..7f
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, // 80..9f
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, // a0..bf
    8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // c0..df
    0xa,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3, // e0..ef
    0xb,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8, // f0..ff
    0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1, // s0..s0
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1, // s1..s2
    1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1, // s3..s4
    1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1, // s5..s6
    1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // s7..s8
};

uint32_t inline decode(uint32_t* state, uint32_t* codep, uint32_t byte)
{
    uint32_t type = utf8d[byte];
    
    *codep = (*state != UTF8_ACCEPT) ?
    (byte & 0x3fu) | (*codep << 6) :
    (0xff >> type) & (byte);
    
    *state = utf8d[256 + *state*16 + type];
    return *state;
}

const char *BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void _base64_encode_triple(unsigned char triple[3], char result[4])
{
    int tripleValue, i;
    
    tripleValue = triple[0];
    tripleValue *= 256;
    tripleValue += triple[1];
    tripleValue *= 256;
    tripleValue += triple[2];
    
    for (i=0; i<4; i++)
    {
        result[3-i] = BASE64_CHARS[tripleValue%64];
        tripleValue /= 64;
    }
}

int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen)
{
    if ((sourcelen+2)/3*4 > targetlen-1)
        return 0;
    
    while (sourcelen >= 3)
    {
        _base64_encode_triple(source, target);
        sourcelen -= 3;
        source += 3;
        target += 4;
    }
    
    if (sourcelen > 0)
    {
        unsigned char temp[3];
        memset(temp, 0, sizeof(temp));
        memcpy(temp, source, sourcelen);
        _base64_encode_triple(temp, target);
        target[3] = '=';
        if (sourcelen == 1)
            target[2] = '=';
        
        target += 4;
    }
    
    target[0] = 0;
    
    return 1;
}

int _base64_char_value(char base64char)
{
    if (base64char >= 'A' && base64char <= 'Z')
        return base64char-'A';
    if (base64char >= 'a' && base64char <= 'z')
        return base64char-'a'+26;
    if (base64char >= '0' && base64char <= '9')
        return base64char-'0'+2*26;
    if (base64char == '+')
        return 2*26+10;
    if (base64char == '/')
        return 2*26+11;
    return -1;
}

int _base64_decode_triple(char quadruple[4], unsigned char *result)
{
    int i, triple_value, bytes_to_decode = 3, only_equals_yet = 1;
    int char_value[4];
    
    for (i=0; i<4; i++)
        char_value[i] = _base64_char_value(quadruple[i]);
    
    for (i=3; i>=0; i--)
    {
        if (char_value[i]<0)
        {
            if (only_equals_yet && quadruple[i]=='=')
            {
                char_value[i]=0;
                bytes_to_decode--;
                continue;
            }
            return 0;
        }
        only_equals_yet = 0;
    }
    
    if (bytes_to_decode < 0)
        bytes_to_decode = 0;
    
    triple_value = char_value[0];
    triple_value *= 64;
    triple_value += char_value[1];
    triple_value *= 64;
    triple_value += char_value[2];
    triple_value *= 64;
    triple_value += char_value[3];
    
    for (i=bytes_to_decode; i<3; i++)
        triple_value /= 256;
    for (i=bytes_to_decode-1; i>=0; i--)
    {
        result[i] = triple_value%256;
        triple_value /= 256;
    }
    
    return bytes_to_decode;
}

size_t base64_decode(char *source, unsigned char *target, size_t targetlen)
{
    char *src, *tmpptr;
    char quadruple[4];
    unsigned char tmpresult[3];
    int i, tmplen = 3;
    size_t converted = 0;
    
    src = (char *)lws_malloc(strlen(source)+5);
    if (src == NULL)
        return -1;
    strcpy(src, source);
    strcat(src, "====");
    tmpptr = src;
    
    while (tmplen == 3)
    {
        for (i=0; i<4; i++)
        {
            while (*tmpptr != '=' && _base64_char_value(*tmpptr)<0)
                tmpptr++;
            
            quadruple[i] = *(tmpptr++);
        }
        
        tmplen = _base64_decode_triple(quadruple, tmpresult);
        
        if (targetlen < tmplen)
        {
            lws_free(src);
            return -1;
        }
        
        memcpy(target, tmpresult, tmplen);
        target += tmplen;
        targetlen -= tmplen;
        converted += tmplen;
    }
    
    lws_free(src);
    return converted;
}

void SHA1Reset(SHA1Context *context)
{
    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;
    
    context->Message_Digest[0]      = 0x67452301;
    context->Message_Digest[1]      = 0xEFCDAB89;
    context->Message_Digest[2]      = 0x98BADCFE;
    context->Message_Digest[3]      = 0x10325476;
    context->Message_Digest[4]      = 0xC3D2E1F0;
    
    context->Computed   = 0;
    context->Corrupted  = 0;
}

int SHA1Result(SHA1Context *context)
{
    
    if (context->Corrupted)
    {
        return 0;
    }
    
    if (!context->Computed)
    {
        SHA1PadMessage(context);
        context->Computed = 1;
    }
    
    return 1;
}

void SHA1Input(     SHA1Context         *context,
               const unsigned char *message_array,
               unsigned            length)
{
    if (!length)
    {
        return;
    }
    
    if (context->Computed || context->Corrupted)
    {
        context->Corrupted = 1;
        return;
    }
    
    while(length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
        (*message_array & 0xFF);
        
        context->Length_Low += 8;
        /* Force it to 32 bits */
        context->Length_Low &= 0xFFFFFFFF;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            /* Force it to 32 bits */
            context->Length_High &= 0xFFFFFFFF;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }
        
        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }
        
        message_array++;
    }
}

void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const unsigned K[] =            /* Constants defined in SHA-1   */
    {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
    int         t;                  /* Loop counter                 */
    unsigned    temp;               /* Temporary word value         */
    unsigned    W[80];              /* Word sequence                */
    unsigned    A, B, C, D, E;      /* Word buffers                 */
    
    /*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t]  = ((unsigned) context->Message_Block[t * 4]) << 24;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 3]);
    }
    
    for(t = 16; t < 80; t++)
    {
        W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }
    
    A = context->Message_Digest[0];
    B = context->Message_Digest[1];
    C = context->Message_Digest[2];
    D = context->Message_Digest[3];
    E = context->Message_Digest[4];
    
    for(t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) +
        ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    
    for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    
    for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
        ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    
    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    
    context->Message_Digest[0] =
    (context->Message_Digest[0] + A) & 0xFFFFFFFF;
    context->Message_Digest[1] =
    (context->Message_Digest[1] + B) & 0xFFFFFFFF;
    context->Message_Digest[2] =
    (context->Message_Digest[2] + C) & 0xFFFFFFFF;
    context->Message_Digest[3] =
    (context->Message_Digest[3] + D) & 0xFFFFFFFF;
    context->Message_Digest[4] =
    (context->Message_Digest[4] + E) & 0xFFFFFFFF;
    
    context->Message_Block_Index = 0;
}

void SHA1PadMessage(SHA1Context *context)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
        
        SHA1ProcessMessageBlock(context);
        
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    
    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = (context->Length_High >> 24) & 0xFF;
    context->Message_Block[57] = (context->Length_High >> 16) & 0xFF;
    context->Message_Block[58] = (context->Length_High >> 8) & 0xFF;
    context->Message_Block[59] = (context->Length_High) & 0xFF;
    context->Message_Block[60] = (context->Length_Low >> 24) & 0xFF;
    context->Message_Block[61] = (context->Length_Low >> 16) & 0xFF;
    context->Message_Block[62] = (context->Length_Low >> 8) & 0xFF;
    context->Message_Block[63] = (context->Length_Low) & 0xFF;
    
    SHA1ProcessMessageBlock(context);
}
