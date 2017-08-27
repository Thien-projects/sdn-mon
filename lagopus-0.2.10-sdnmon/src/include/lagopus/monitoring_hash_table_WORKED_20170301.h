/*
 * monitoring_hash_table.h
 *
 *  Created on: Apr 24, 2016
 *      Author: thienphan
 */

#ifndef SRC_INCLUDE_LAGOPUS_MONITORING_HASH_TABLE_H_
#define SRC_INCLUDE_LAGOPUS_MONITORING_HASH_TABLE_H_

/*-
 * Copyright (c) 1988, 1989, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 1988, 1989 by Adam de Boor
 * Copyright (c) 1989 by Berkeley Softworks
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Adam de Boor.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)hash.h	8.1 (Berkeley) 6/6/93
 * $FreeBSD: src/usr.bin/make/hash.h,v 1.20 2005/05/13 08:53:00 harti Exp $
 */

/* hash.h --
 *
 * 	This file contains definitions used by the hash module,
 * 	which maintains hash tables.
 */


//#include "pktbuf.h"
//#include "openflow13.h"
#include "lagopus_apis.h"
#include "openflow.h"
//#include "ofcache.h"

//#include "lagopus/monitoringdb.h"
////#include "util.h"
//#include "stdio.h"
//#include <stdbool.h>
//#include "lagopus_apis.h"
//#include "openflow.h"
//#include "pktbuf.h"

/*
 * The following defines one entry in the hash table.
 */
typedef struct Hash_Entry {
	struct Hash_Entry *next;	/* Link entries within same bucket. */

	//void		*clientData;	/* Data associated with key. */
	//struct m_entry *m_entry;
	  struct m_key *m_key;
	  //struct statistics **stats_list;
	  //int n_stats; /*number of statistics items in this m_entry, correspond to number of statistics fields in m_table,
	  	  	  	  	 /*this value can be adjusted by controller*/
	  uint64_t packet_count;
	  uint64_t byte_count;
	  /* Creation time. */
	  struct timespec create_time;
	  /* Last updated time. */
	  struct timespec update_time;

	unsigned	namehash;	/* hash value of key */
	char		name[1];	/* key string */
} Hash_Entry;

typedef struct Hash_Table {
	struct Hash_Entry **bucketPtr;	/* Buckets in the table */
	int 		size;		/* Actual size of array. */
	int 		numEntries;	/* Number of entries in the table. */
	int 		mask;		/* Used to select bits for hashing. */
	int 		numBuckets; /*number of buckets in Hash Table*/
} Hash_Table;

/*
 * The following structure is used by the searching routines
 * to record where we are in the search.
 */
typedef struct Hash_Search {
	const Hash_Table *tablePtr;	/* Table being searched. */
	int		nextIndex;	/* Next bucket to check */
	Hash_Entry 	*hashEntryPtr;	/* Next entry in current bucket */
} Hash_Search;

/*
 * Macros.
 */

/*
 * void *Hash_GetValue(const Hash_Entry *h)
 */
//#define	Hash_GetValue(h) ((h)->clientData)
#define	Hash_Get_M_Entry(h) ((h)->m_entry)

/*
 * Hash_SetValue(Hash_Entry *h, void *val);
 */
//#define	Hash_SetValue(h, val) ((h)->clientData = (val))
#define	Hash_Set_M_Entry(h, m_entry) ((h)->m_entry = (m_entry))

//void Hash_InitTable(Hash_Table *, int);
unsigned int m_hash(const char *s, int m);

struct Hash_Table *allocHashTable(int numBuckets);

void Hash_DeleteTable(Hash_Table *t);

void HashTable_Reset_Table(struct Hash_Table *t);

struct Hash_Entry *HashTable_Find_And_Update_Entry(struct Hash_Table *t, struct lagopus_packet *pkt, char *key);

struct Hash_Entry *HashTable_Add_Entry(struct Hash_Table *t, struct lagopus_packet *pkt, struct m_key *m_key, const char *key, bool *newPtr);
struct Hash_Entry *
HashTable_Add_Entry_From_Controller(struct Hash_Table *t, struct m_key *m_key, const char *key, bool *newPtr);

void HashTable_Find_And_Delete_Entry(struct Hash_Table *t, char *key);
void HashTable_Delete_Entry(struct Hash_Table *t, struct Hash_Entry *e);

struct Hash_Entry *Hash_EnumFirst(struct Hash_Table *t, struct Hash_Search *searchPtr);
struct Hash_Entry *Hash_EnumNext(struct Hash_Search *searchPtr);

/*
 * @THIEN: 2016-05-09
 * Traverse Hash Table and collect stats of all Hash Entries
 * Return: m_entry_stats_list: a list of m_entry_stats (of all m_entry/hash entry)
 */
/*lagopus_result_t
hashTable_Get_Entry_Stats(struct Hash_Table *t, struct m_entry_stats_list *m_entry_stats_list);
*/

void printHashTable(struct Hash_Table *t); //@Thien, 2016-05-01
void printHashEntry(struct Hash_Entry *e);

#endif /* SRC_INCLUDE_LAGOPUS_MONITORING_HASH_TABLE_H_ */
