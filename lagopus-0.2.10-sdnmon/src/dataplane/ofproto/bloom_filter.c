/*******************************************************************************
*
* bloom_filter.c -- A simple bloom filter implementation
* by timdoug -- timdoug@gmail.com -- http://www.timdoug.com -- 2008-07-05
* see http://en.wikipedia.org/wiki/Bloom_filter
*
********************************************************************************
*
* Copyright (c) 2008, timdoug(@gmail.com) -- except for the hash functions
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * The name of the author may not be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY timdoug ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL timdoug BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
********************************************************************************
*
* compile with (note -- ints should be >= 32 bits):
* gcc -Wall -Werror -g -ansi -pedantic -O2 bloom_filter.c -o bloom_filter
*
* example usage ("words" is from /usr/share/dict/words on debian):
* $ ./bloom_filter
* usage: ./bloom_filter dictionary word ...
* $ ./bloom_filter words test word words foo bar baz not_in_dict
* "test" in dictionary
* "word" in dictionary
* "words" in dictionary
* "foo" not in dictionary
* "bar" in dictionary
* "baz" not in dictionary
* "not_in_dict" not in dictionary
*
* this implementation uses 7 hash functions, the optimal number for an input
* of approx. 100,000 and a filter size of 2^20 bits -- a ~7.2x decrease in
* space needed (from 912KB to 128KB), with an false positive rate of 0.007.
* consult Wikipedia for optimal numbers for your input and desired size
*
* all the hash functions are under the Common Public License and from:
* http://www.partow.net/programming/hashfunctions/index.html
* although I haven't rigorously tested them -- for real use, you'll probably
* want to make sure they work well for your data set or choose others.
*
* other hash functions of interest:
* http://www.cse.yorku.ca/~oz/hash.html
* http://www.isthe.com/chongo/tech/comp/fnv/
* http://www.azillionmonkeys.com/qed/hash.html
* http://murmurhash.googlepages.com/
*
*******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

//#include <bloom_filter.h>
#include "lagopus/bloom_filter.h"

/*int main(int argc, char *argv[])
{
	unsigned char filter[FILTER_SIZE_BYTES];
	int i;

	if (argc < 3)
		err("usage: %s dictionary word ...\n", argv[0]);

	for (i = 0; i < FILTER_SIZE_BYTES; i++)
		filter[i] = 0;

	load_words(filter, argv[1]);
		
	for (i = 2; i < argc; i++) {
		if (in_dict(filter, argv[i]))
			printf("\"%s\" in dictionary\n", argv[i]);
		else
			printf("\"%s\" not in dictionary\n", argv[i]);
	}

	return 0;
}*/

/*struct bloom_filer *bloom_filter_alloc(){
	unsigned char filter[FILTER_SIZE_BYTES];
	for (int i = 0; i < FILTER_SIZE_BYTES; i++)
		filter[i] = 0;
	return filter;
}*/
struct bloom_filter *bloom_filter_alloc(){
	  struct bloom_filter *bloom_filter;
	  bloom_filter = (struct bloom_filter *)calloc(1, sizeof(struct bloom_filter)); //sizeof(unsigned char*)*FILTER_SIZE_BYTES);
	  if (bloom_filter == NULL) {
		printf("prinf-Error: bloom_filter calloc FAILED!");
	    return NULL;
	  }
//	unsigned char filter[FILTER_SIZE_BYTES];
	for (int i = 0; i < FILTER_SIZE_BYTES; i++)
		bloom_filter->filter[i] = 0;
	//unsigned char *ft = filter;
	//bloom_filter->filter = filter;
	return bloom_filter;
}


/*void err(char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	exit(-1);
}
/*

/*void load_words(unsigned char filter[], char *filename)
{
	FILE *dict = fopen(filename, "r");
	char buf[WORD_BUF_SIZE];
	int c, pos = 0;

	if (!dict)
		err("unable to open dictionary \"%s\"\n", filename);
	
	while ((c = getc(dict)) != EOF) {
		if (c != '\n') {
			if (pos > WORD_BUF_SIZE-2) {
				buf[WORD_BUF_SIZE-1] = 0;
				err("word \"%s\" exceeds buffer length\n", buf);
			} else {
				buf[pos++] = c;
			}
		} else {
			buf[pos] = 0;
			insert_word(filter, buf);
			pos = 0;
		}
	}
	
	fclose(dict);
}*/


/*void bloom_filter_insert(unsigned char filter[], char *str)
{
	unsigned int hash[NUM_HASHES];
	int i;

	get_hashes(hash, str);

	for (i = 0; i < NUM_HASHES; i++) {
		 xor-fold the hash into FILTER_SIZE bits
		hash[i] = (hash[i] >> FILTER_SIZE) ^
		          (hash[i] & FILTER_BITMASK);
		 set the bit in the filter
		filter[hash[i] >> 3] |= 1 << (hash[i] & 7);
	}
}*/

/*
void bloom_filter_insert(struct bloom_filter *bloom_filter, char *str)
{
	unsigned int hash[NUM_HASHES];
	int i;
	
	get_hashes(hash, str);
	
	for (i = 0; i < NUM_HASHES; i++) {
		// xor-fold the hash into FILTER_SIZE bits
		hash[i] = (hash[i] >> FILTER_SIZE) ^ 
		          (hash[i] & FILTER_BITMASK);
		// set the bit in the filter
		bloom_filter->filter[hash[i] >> 3] |= 1 << (hash[i] & 7);
	}
}
*/
//Updated 2017-04-13
void bloom_filter_insert(struct bloom_filter *bloom_filter, unsigned int entry_hash_value)
{
	unsigned int hash[NUM_HASHES];
	int i;

	get_hashes(hash, entry_hash_value);

	for (i = 0; i < NUM_HASHES; i++) {
		/* xor-fold the hash into FILTER_SIZE bits */
		hash[i] = (hash[i] >> FILTER_SIZE) ^
		          (hash[i] & FILTER_BITMASK);
		/* set the bit in the filter */
		bloom_filter->filter[hash[i] >> 3] |= 1 << (hash[i] & 7);
	}
}

/*int bloom_filter_check(unsigned char filter[], char *str)
{
	unsigned int hash[NUM_HASHES];
	int i;

	get_hashes(hash, str);

	for (i = 0; i < NUM_HASHES; i++) {
		hash[i] = (hash[i] >> FILTER_SIZE) ^
		          (hash[i] & FILTER_BITMASK);
		if (!(filter[hash[i] >> 3] & (1 << (hash[i] & 7))))
			return 0;
	}

	return 1;
}*/

/*
int bloom_filter_check(struct bloom_filter *bloom_filter, char *str)
{
	unsigned int hash[NUM_HASHES];
	int i;

	get_hashes(hash, str);

	for (i = 0; i < NUM_HASHES; i++) {
		hash[i] = (hash[i] >> FILTER_SIZE) ^
		          (hash[i] & FILTER_BITMASK);
		if (!(bloom_filter->filter[hash[i] >> 3] & (1 << (hash[i] & 7))))
			return 0;
	}

	return 1;
}
*/
//Updated 2017-04-13
int bloom_filter_check(struct bloom_filter *bloom_filter, unsigned int entry_hash_value)
{
	unsigned int hash[NUM_HASHES];
	int i;
	
	get_hashes(hash, entry_hash_value);
	
	for (i = 0; i < NUM_HASHES; i++) {
		hash[i] = (hash[i] >> FILTER_SIZE) ^
		          (hash[i] & FILTER_BITMASK);
		if (!(bloom_filter->filter[hash[i] >> 3] & (1 << (hash[i] & 7))))
			return 0;
	}
	
	return 1;
}

/*
void get_hashes(unsigned int hash[], char *in)
{
	unsigned char *str = (unsigned char *)in;
	int pos = strlen(in);
	hash[0] = RSHash  (str, pos);
//	hash[1] = DJBHash (str, pos);
//	hash[2] = FNVHash (str, pos);
//	hash[3] = JSHash  (str, pos);
//	hash[4] = PJWHash (str, pos);
//	hash[5] = SDBMHash(str, pos);
//	hash[6] = DEKHash (str, pos);
}
*/
//Updated 2017-04-13
void get_hashes(unsigned int hash[], unsigned int entry_hash_value)
{

	hash[0] = entry_hash_value >> 8 | entry_hash_value << 24;
	hash[1] = entry_hash_value >> 16 | entry_hash_value << 16;
	hash[2] = entry_hash_value >> 24 | entry_hash_value << 8;
	//	hash[1] = DJBHash (str, pos);
//	hash[2] = FNVHash (str, pos);
//	hash[3] = JSHash  (str, pos);
//	hash[4] = PJWHash (str, pos);
//	hash[5] = SDBMHash(str, pos);
//	hash[6] = DEKHash (str, pos);
}



/****************\
| Hash Functions |
\****************/

unsigned int RSHash(unsigned char *str, unsigned int len)
{
   unsigned int b    = 378551;
   unsigned int a    = 63689;
   unsigned int hash = 0;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = hash * a + (*str);
      a    = a * b;
   }

   return hash;
}

unsigned int JSHash(unsigned char *str, unsigned int len)
{
   unsigned int hash = 1315423911;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash ^= ((hash << 5) + (*str) + (hash >> 2));
   }

   return hash;
}

unsigned int PJWHash(unsigned char *str, unsigned int len)
{
   const unsigned int BitsInUnsignedInt = (unsigned int)(sizeof(unsigned int) * 8);
   const unsigned int ThreeQuarters     = (unsigned int)((BitsInUnsignedInt  * 3) / 4);
   const unsigned int OneEighth         = (unsigned int)(BitsInUnsignedInt / 8);
   const unsigned int HighBits          = (unsigned int)(0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
   unsigned int hash              = 0;
   unsigned int test              = 0;
   unsigned int i                 = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (hash << OneEighth) + (*str);

      if((test = hash & HighBits)  != 0)
      {
         hash = (( hash ^ (test >> ThreeQuarters)) & (~HighBits));
      }
   }

   return hash;
}

unsigned int SDBMHash(unsigned char *str, unsigned int len)
{
   unsigned int hash = 0;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (*str) + (hash << 6) + (hash << 16) - hash;
   }

   return hash;
}

unsigned int DJBHash(unsigned char *str, unsigned int len)
{
   unsigned int hash = 5381;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = ((hash << 5) + hash) + (*str);
   }

   return hash;
}

unsigned int DEKHash(unsigned char *str, unsigned int len)
{
   unsigned int hash = len;
   unsigned int i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = ((hash << 5) ^ (hash >> 27)) ^ (*str);
   }
   return hash;
}

unsigned int FNVHash(unsigned char *str, unsigned int len)
{
   const unsigned int fnv_prime = 0x811C9DC5;
   unsigned int hash      = 0;
   unsigned int i         = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash *= fnv_prime;
      hash ^= (*str);
   }

   return hash;
}

void bloom_filter_cleanup(struct bloom_filter *bloom_filter){
	for (int i = 0; i < FILTER_SIZE_BYTES; i++)
		bloom_filter->filter[i] = 0;
}

void bloom_filter_free(struct bloom_filter *bloom_filter){
	free(bloom_filter);
}
