/*
 * bloom_filter.h
 *
 *  Created on: Mar 1, 2016
 *      Author: root
 */

#ifndef BLOOM_FILTER_H_
#define BLOOM_FILTER_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/* config options */
/* 2^FILTER_SIZE is the size of the filter in bits, i.e.,
 * size 20 = 2^20 bits = 1 048 576 bits = 131 072 bytes = 128 KB */
#define FILTER_SIZE 20
#define NUM_HASHES 3 //7
#define WORD_BUF_SIZE 32

#define FILTER_SIZE_BYTES (1 << (FILTER_SIZE - 3))
#define FILTER_BITMASK ((1 << FILTER_SIZE) - 1)

struct bloom_filter{
	unsigned char filter[FILTER_SIZE_BYTES];
	//int filter_size;
};


//int init_bloom_filter(unsigned char filter[], int filter_size);
struct bloom_filter *bloom_filter_alloc();

/* hash functions */
unsigned int RSHash  (unsigned char *, unsigned int);
unsigned int DJBHash (unsigned char *, unsigned int);
unsigned int FNVHash (unsigned char *, unsigned int);
unsigned int JSHash  (unsigned char *, unsigned int);
unsigned int PJWHash (unsigned char *, unsigned int);
unsigned int SDBMHash(unsigned char *, unsigned int);
unsigned int DEKHash (unsigned char *, unsigned int);

/* helper functions */
//void err(char *msg, ...);

//void load_words(unsigned char[], char *);
/*void bloom_filter_insert(unsigned char[], char *);
int bloom_filter_check(unsigned char[], char *);
void get_hashes(unsigned int[], char *);*/

/*
void bloom_filter_insert(struct bloom_filter *bloom_filter, char *str);
int bloom_filter_check(struct bloom_filter *bloom_filter, char *str);
void get_hashes(unsigned int[], char *);
*/
//Updated by @Thien Phan, 2017-04-13
void bloom_filter_insert(struct bloom_filter *bloom_filter, unsigned int entry_hash_value);
int bloom_filter_check(struct bloom_filter *bloom_filter, unsigned int entry_hash_value);
void get_hashes(unsigned int[], unsigned int entry_hash_value);

void bloom_filter_cleanup(struct bloom_filter *bloom_filter);
void bloom_filter_free(struct bloom_filter *bloom_filter);

#endif /* BLOOM_FILTER_H_ */
