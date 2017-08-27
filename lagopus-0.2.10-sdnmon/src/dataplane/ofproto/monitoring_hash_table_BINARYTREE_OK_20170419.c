/*
 * monitoring_hash_table.c
 *
 *  Created on: Apr 24, 2016
 *      Author: thienphan
 */

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
 * @(#)hash.c	8.1 (Berkeley) 6/6/93
 */

#include <sys/cdefs.h>
//__FBSDID("$FreeBSD: src/usr.bin/make/hash.c,v 1.25 2005/05/13 08:53:00 harti Exp $");

#include "lagopus_config.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

//#include <openflow.h>

//#include "lagopus/dpmgr.h"
#include "lagopus/ofp_handler.h"
#include "lagopus/ethertype.h"
//#include "lagopus/vector.h"
#include "lagopus/bridge.h"
#include "lagopus/port.h"
#include "lagopus/group.h"
#include "lagopus/meter.h"
#include "lagopus/dataplane.h"
#include "lagopus/ofcache.h"
#include "lagopus/ofp_dp_apis.h"
#include "../agent/ofp_match.h"
#include "pktbuf.h"
#include "packet.h"
#include "csum.h"
#include "pcap.h"
#include "City.h"
#include "murmurhash3.h"

//#include "openflow13.h"
#include "lagopus_apis.h"
#include "openflow.h"
//#include "ofcache.h"

#include "stdio.h"
//#include "lagopus/monitoringdb.h"
#include "lagopus/monitoring_hash_table.h"

//#include <stdbool.h>
//#include "lagopus_apis.h"
//#include "openflow.h"
/* hash.c --
 *
 * 	This module contains routines to manipulate a hash table.
 * 	See hash.h for a definition of the structure of the hash
 * 	table.  Hash tables grow automatically as the amount of
 * 	information increases.
 */

//#include <stdlib.h>
//#include <string.h>
//#include <unistd.h>
//
//#include "stdio.h"
//#include <inttypes.h>
//#include <stdint.h>
//#include "pktbuf.h"
////#include "packet.h"
//#include "lagopus/dpmgr.h"
//#include "util.h"

/*
 * Forward references to local procedures that are used before they're
 * defined:
 */
static void RebuildTable(Hash_Table *);

/*
 * The following defines the ratio of # entries to # buckets
 * at which we rebuild the table to make it larger.
 */

#define	rebuildLimit 8

/*
 *---------------------------------------------------------
 *
 * Hash_InitTable --
 *
 * 	Set up the hash table t with a given number of buckets, or a
 * 	reasonable default if the number requested is less than or
 * 	equal to zero.  Hash tables will grow in size as needed.
 *
 *
 * Results:
 *	None.
 *
 * Side Effects:
 *	Memory is allocated for the initial bucket area.
 *
 *---------------------------------------------------------
 */

/*
 * @Thien Phan
 * 2017-04-07
 * BINARY SEARCH TREE functions
 *
 */
 // A utility function to create a new BST node
 struct Hash_Entry *new_binary_node(uint64_t byte_count_of_arriving_entry, struct m_key *m_key, unsigned int entry_hash_value)
 {
     struct Hash_Entry *e =  (struct Hash_Entry *)malloc(sizeof(struct Hash_Entry));
     e->left = e->right = NULL;
     e->m_key = m_key;
     e->packet_count = 1;
     e->byte_count = byte_count_of_arriving_entry; //OS_M_PKTLEN(PKT2MBUF(pkt)); //OS_M_PKTLEN(pkt->mbuf);
 	e->create_time = get_current_time();
 	e->update_time = e->create_time;
 	//
 	e->check_updated_entry = 0; //to mark this as brand new entry.

 	e->namehash = entry_hash_value; //hash_value;
     return e;
 }

 /* A utility function to insert a new node with given key in BST */
 struct Hash_Entry* insert_binary(struct Hash_Entry* node, uint64_t byte_count_of_arriving_entry, struct m_key *m_key, unsigned int key)
 {
     /* If the tree is empty, return a new node */
     if (node == NULL) return new_binary_node(byte_count_of_arriving_entry, m_key, key);

     /* Otherwise, recur down the tree */
     if (key < node->namehash)
         node->left  = insert_binary(node->left, byte_count_of_arriving_entry, m_key, key);
     else
         node->right = insert_binary(node->right, byte_count_of_arriving_entry, m_key, key);

     /* return the (unchanged) node pointer */
     return node;
 }

 struct Hash_Entry* search_binary(struct Hash_Entry* node, unsigned int key){
 	if(node == NULL)
 		return NULL;
 	if(node->namehash == key)
 		return node;
 	if(key < node->namehash)
 		return search_binary(node->left, key);
 	else
 		return search_binary(node->right, key);
 }

 struct Hash_Entry* search_and_update_entry_binary(struct Hash_Entry* node, uint64_t byte_count_of_arriving_packet, unsigned int key){
	 //printf("1.3.1\n");
	 if(node == NULL)
 		return NULL;
	 //printf("1.3.2\n");
 	if(node->namehash == key){
 		node->packet_count++;
 		node->byte_count += byte_count_of_arriving_packet;
 		node->update_time = get_current_time();
 		node->check_updated_entry = 1; //to mark this as an updated entry
 		return node;
 	}
 	//printf("1.3.3\n");
 	if(key < node->namehash){
 		//printf("1.3.4\n");
 		return search_and_update_entry_binary(node->left, byte_count_of_arriving_packet, key);
 	}else{
 		//printf("1.3.5\n");
 		return search_and_update_entry_binary(node->right, byte_count_of_arriving_packet, key);
 	}
 }

 void delete_binary_tree(struct Hash_Entry *root)
 {
     if (root != NULL)
     {
    	 delete_binary_tree(root->left);
    	 delete_binary_tree(root->right);
    	 free(root);
     }
 }

//HASH FUNCTION: creat hash value from char*
 /* treat strings as base-256 integers */
 /* with digits in the range 1 to 255 */
 #define BASE (256)

 unsigned int m_hash(const char *s, int m) //unsigned long m)
 {
     unsigned int h;
     unsigned const char *us;

     /* cast s to unsigned const char * */
     /* this ensures that elements of s will be treated as having values >= 0 */
     us = (unsigned const char *) s;

     h = 0;
     while(*us != '\0') {
         h = (h * BASE + *us) % m;
         us++;
     }

     return h;
 }

//void Hash_InitTable(Hash_Table *t, int numBuckets)
struct Hash_Table *allocHashTable(int numBuckets)
{
	int i;
	struct Hash_Entry **hp;

	struct Hash_Table *t;

	printf("numBuckets = %d\n", numBuckets);

	t = (struct Hash_Table *)calloc(1, sizeof(struct Hash_Table));
	  if (t == NULL) {
	    return NULL;
	  }
	t->numBuckets = numBuckets;

	/*
	 * Round up the size to a power of two.
	 */
/*	if (numBuckets <= 0)
		i = 16;
	else {
		for (i = 2; i < numBuckets; i <<= 1)
			 continue;
	}
*/
	i = numBuckets;
	t->numEntries = 0;
	t->size = i;
	t->mask = i - 1;
	//t->bucketPtr = hp = malloc(sizeof(*hp) * i); //(struct Hash_Entry *)calloc(1, sizeof(struct Hash_Entry)*i); //malloc(sizeof(*hp) * i);
	//t->bucketPtr = hp = calloc(i, sizeof(*hp));
	t->bucketPtr = hp = calloc(i, sizeof(struct Hash_Entry));
	while (--i >= 0)
		*hp++ = NULL;

	return t;
}

/*
 *---------------------------------------------------------
 *
 * Hash_DeleteTable --
 *
 *	This routine removes everything from a hash table
 *	and frees up the memory space it occupied (except for
 *	the space in the Hash_Table structure).
 *
 * Results:
 *	None.
 *
 * Side Effects:
 *	Lots of memory is freed up.
 *
 *---------------------------------------------------------
 */
/*
void
Hash_DeleteTable(Hash_Table *t)
{
	printf("Hash_DeleteTable called\n");
	struct Hash_Entry **hp, *h, *nexth = NULL;
	int i;

	for (hp = t->bucketPtr, i = t->size; --i >= 0;) {
		for (h = *hp++; h != NULL; h = nexth) {
			nexth = h->next;
			free(h);
		}
	}
	free(t->bucketPtr);


	 // Set up the hash table to cause memory faults on any future access
	 // attempts until re-initialization.

	t->bucketPtr = NULL;
	printf("Deleted Hash Table\n");
}
*/

/*
 * @Thien Phan
 * 2017-04-17
 * Hash_DeleteTable(): Modified for HashTable + Binary Search Tree
 */
void
Hash_DeleteTable(Hash_Table *t)
{
	printf("Hash_DeleteTable called\n");
	struct Hash_Entry **hp, *h; //, *nexth = NULL;
	int i;

	for (hp = t->bucketPtr, i = t->size; --i >= 0;) {
		h = *hp++;
		delete_binary_tree(h);
		/*for (h = *hp++; h != NULL; h = nexth) {
			nexth = h->next;
			free(h);
		}*/
	}
	free(t->bucketPtr);

	/*
	 * Set up the hash table to cause memory faults on any future access
	 * attempts until re-initialization.
	 */
	t->bucketPtr = NULL;
	printf("Deleted Hash Table\n");
}

void
HashTable_Reset_Table(struct Hash_Table *t){
/*	struct Hash_Entry **hp, *h, *nexth = NULL;
	int i;

	for (hp = t->bucketPtr, i = t->size; --i >= 0;) {
		for (h = *hp++; h != NULL; h = nexth) {
			nexth = h->next;
			free(h);
		}
	}
	//free(t->bucketPtr);

	t = (struct Hash_Table *)calloc(1, sizeof(struct Hash_Table));
	  if (t == NULL) {
	    return NULL;
	  }
	i = t->numBuckets;
	t->numEntries = 0;
	t->size = i;
	t->mask = i - 1;
	//t->bucketPtr = hp = malloc(sizeof(*hp) * i); //(struct Hash_Entry *)calloc(1, sizeof(struct Hash_Entry)*i); //malloc(sizeof(*hp) * i);
	//t->bucketPtr = hp = calloc(i, sizeof(*hp));
	t->bucketPtr = hp = calloc(i, sizeof(struct Hash_Entry));
	while (--i >= 0)
		*hp++ = NULL;

	printf("RESET Hash Table\n");
	//t = allocHashTable(t->numBuckets);
*/
}

/*
 * @Xuan Thien Phan
 * 2017-04-13
 * Hash function to calculate hash value of a m-entry
 */
unsigned int hash(char* key){
	unsigned int h;
	const char *p;
	for (h = 0, p = key; *p;)
		h = (h << 5) - h + *p++;
	return h;
}

/*
 *---------------------------------------------------------
 *
 * Hash_FindEntry --
 *
 * 	Searches a hash table for an entry corresponding to key.
 *
 * Results:
 *	The return value is a pointer to the entry for key,
 *	if key was present in the table.  If key was not
 *	present, NULL is returned.
 *
 * Side Effects:
 *	None.
 *
 *---------------------------------------------------------
 */
//If not found, return NULL. If found, update entry.
/*
struct Hash_Entry *
HashTable_Find_And_Update_Entry(struct Hash_Table *t, struct lagopus_packet *pkt, char *key)
{
	Hash_Entry *e;
	unsigned int h;
	const char *p;
	//unsigned int hash_value;

//	for (h = 0, p = key; *p;)
//		h = (h << 5) - h + *p++;
	h = hash(key);
	p = key;

	//hash_value = h & t->mask;  // m_hash(key, t->size);
//	printf("hash_value = %d\n", hash_value);


//	printf("Thien checkpoint 3.1.1\n");
//	printf("table size t->size = %d\n", t->size);
//	printf("t->mask = %d\n", t->mask);
//	printf("h&t->mask = %d\n", h & t->mask);
	//for (e = t->bucketPtr[h & t->mask]; e != NULL; e = e->next)
	//e = t->bucketPtr[hash_value];
//	if(e == NULL)
//		printf("e == NULL");
//	else
//		printf("e != NULL");
//	printf("Thien checkpoint 3.1.2\n");

	for (e = t->bucketPtr[h & t->mask]; e != NULL; e = e->next){
//		printf("Thien checkpoint 3.1.3\n");
		//If found entry, update it's statistics then return the entry.
		if (e->namehash == h && strcmp(e->name, p) == 0){
			e->packet_count++;
			e->byte_count += OS_M_PKTLEN(PKT2MBUF(pkt)); //OS_M_PKTLEN(pkt->mbuf);
			e->update_time = get_current_time();

			//
			e->check_updated_entry = 1; //to mark this as an updated entry
										//(an existring one in m-table but has counters updated.)

			return e;
		}
	}
//	printf("Thien checkpoint 3.1.8\n");

	return NULL;
}
*/



/*
 * @Xuan Thien Phan
 * 2017-04-13
 * New version of function: HashTable_Find_And_Update_Entry(...)
 */
/*
struct Hash_Entry *
HashTable_Find_And_Update_Entry(struct Hash_Table *t, uint64_t byte_count_of_arriving_packet, unsigned int entry_hash_value)
{
	Hash_Entry *e;
	unsigned int h;
	const char *p;
	//unsigned int hash_value;

	h = entry_hash_value;

	for (e = t->bucketPtr[h & t->mask]; e != NULL; e = e->next){
		//If found entry, update it's statistics then return the entry.
		if (e->namehash == h){ //&& strcmp(e->name, p) == 0){
			e->packet_count++;
			e->byte_count += byte_count_of_arriving_packet; //OS_M_PKTLEN(PKT2MBUF(pkt)); //OS_M_PKTLEN(pkt->mbuf);
			e->update_time = get_current_time();

			e->check_updated_entry = 1; //to mark this as an updated entry
										//(an existring one in m-table but has counters updated.)
			return e;
		}
	}
	return NULL;
}
*/

/*
 * @Xuan Thien Phan
 * 2017-04-17
 * HashTable_Find_And_Update_Entry(...) => Modified for HashTable + Binary Search Tree
 */
struct Hash_Entry *
HashTable_Find_And_Update_Entry(struct Hash_Table *t, uint64_t byte_count_of_arriving_packet, unsigned int entry_hash_value)
{
	Hash_Entry *e;
	//printf("1.1\n");
	e = t->bucketPtr[entry_hash_value & t->mask];
	if(e == NULL)
		return NULL;
	//printf("1.2\n");
	if(e->namehash == entry_hash_value){
		e->packet_count++;
		e->byte_count += byte_count_of_arriving_packet;
		e->update_time = get_current_time();
		e->check_updated_entry = 1; //to mark this as an updated entry
		//printf("1.2.1\n");
		return e;
	}
	//printf("1.3\n");
	return search_and_update_entry_binary(e, byte_count_of_arriving_packet, entry_hash_value);


	/*for (e = t->bucketPtr[entry_hash_value & t->mask]; e != NULL; e = e->next){
		//If found entry, update it's statistics then return the entry.
		if (e->namehash == entry_hash_value){
			e->packet_count++;
			e->byte_count += byte_count_of_arriving_packet;
			e->update_time = get_current_time();

			e->check_updated_entry = 1; //to mark this as an updated entry
										//(an existring one in m-table but has counters updated.)
			return e;
		}
	}
	*/
	//return NULL;
}

/*
 *---------------------------------------------------------
 *
 * Hash_CreateEntry --
 *
 *	Searches a hash table for an entry corresponding to
 *	key.  If no entry is found, then one is created.
 *
 * Results:
 *	The return value is a pointer to the entry.  If *newPtr
 *	isn't NULL, then *newPtr is filled in with TRUE if a
 *	new entry was created, and FALSE if an entry already existed
 *	with the given key.
 *
 * Side Effects:
 *	Memory may be allocated, and the hash buckets may be modified.
 *---------------------------------------------------------
 */
//Create and add a new entry into HashTable, existence of entry was checked in HashTable_Find_And_Update_Entry(...) to be not existed.
/*
struct Hash_Entry *
HashTable_Add_Entry(struct Hash_Table *t, struct lagopus_packet *pkt, struct m_key *m_key, const char *key, bool *newPtr)
{
	Hash_Entry *e;
	unsigned int h;
	const char *p;
	int keylen;
	struct Hash_Entry **hp;
	unsigned int hash_value;


	  //Hash the key.  As a side effect, save the length (strlen) of the
	  //key in case we need to create the entry.


	for (h = 0, p = key; *p;)
		h = (h << 5) - h + *p++;
	keylen = p - key;
	p = key;

	hash_value = h & t->mask; //m_hash(key, t->size);
//	printf("hash_value = %d\n", hash_value);
	//This entry existence check was done at HashTable_Find_And_Update_Entry(...)
	//No need to check again here.



	 // The desired entry isn't there.  Before allocating a new entry,
	 // expand the table if necessary (and this changes the resulting
	 // bucket chain).

	if (t->numEntries >= rebuildLimit * t->size)
		RebuildTable(t);

	//e = (struct Hash_Entry *)calloc(1, sizeof(struct Hash_Entry)); //+ keylen); //emalloc(sizeof(*e) + keylen);
	//hPtr = (HashEntry *)malloc(sizeof(HashEntry) - sizeof(hPtr->key) + tablePtr->keyLen);
	e = malloc(sizeof(*e) + keylen);
	//hp = &t->bucketPtr[h & t->mask];
	hp = &t->bucketPtr[hash_value];
	e->next = *hp;
	*hp = e;

	//Fill up data of monitoring entry
	e->m_key = m_key;
	e->packet_count = 1;
	e->byte_count = OS_M_PKTLEN(PKT2MBUF(pkt)); //OS_M_PKTLEN(pkt->mbuf);
	e->create_time = get_current_time();
	e->update_time = e->create_time;
	//
	e->check_updated_entry = 0; //to mark this as brand new entry.

	e->namehash = h; //hash_value;
	strcpy(e->name, p); //key);
	t->numEntries++;

	if (newPtr != NULL)
		*newPtr = true;
	return e;
}
*/


/*
 * @Xuan Thien Phan
 * 2017-04-13
 * New version of function
 */
/*
struct Hash_Entry *
HashTable_Add_Entry(struct Hash_Table *t, uint64_t byte_count_of_arriving_entry, struct m_key *m_key, unsigned int entry_hash_value, bool *newPtr)
{
	Hash_Entry *e;
	unsigned int h;
	const char *p;
	int keylen;
	struct Hash_Entry **hp;

	/*
	 * Hash the key.  As a side effect, save the length (strlen) of the
	 * key in case we need to create the entry.
	 */

	/*
	//for (h = 0, p = key; *p;)
	//	h = (h << 5) - h + *p++;
	//keylen = p - key;
	//p = key;

	h = entry_hash_value;

	//hash_value = h & t->mask; //m_hash(key, t->size);

	//The entry existence check was done at HashTable_Find_And_Update_Entry(...)
	//No need to check again here.


	 // The desired entry isn't there.  Before allocating a new entry,
	 // expand the table if necessary (and this changes the resulting
	 // bucket chain).

	if (t->numEntries >= rebuildLimit * t->size)
		RebuildTable(t);

	//e = malloc(sizeof(*e) + keylen);
	e = malloc(sizeof(*e));
	hp = &t->bucketPtr[h & t->mask];
	e->next = *hp;
	*hp = e;

	//Fill up data of monitoring entry
	e->m_key = m_key;
	e->packet_count = 1;
	e->byte_count = byte_count_of_arriving_entry; //OS_M_PKTLEN(PKT2MBUF(pkt)); //OS_M_PKTLEN(pkt->mbuf);
	e->create_time = get_current_time();
	e->update_time = e->create_time;
	//
	e->check_updated_entry = 0; //to mark this as brand new entry.

	e->namehash = h; //hash_value;
	//strcpy(e->name, p); //key);
	t->numEntries++;

	if (newPtr != NULL)
		*newPtr = true;
	return e;
}
*/
/*
 * @Xuan Thien Phan
 * 2017-04-17
 * Modified to HashTable + Binary Search Tree
 */
struct Hash_Entry *
HashTable_Add_Entry(struct Hash_Table *t, uint64_t byte_count_of_arriving_entry, struct m_key *m_key, unsigned int entry_hash_value, bool *newPtr)
{
	Hash_Entry *e;
	const char *p;
	int keylen;
	struct Hash_Entry **hp;

	//The entry existence check was done at HashTable_Find_And_Update_Entry(...)
	//No need to check again here.
	/*
	 * The desired entry isn't there.  Before allocating a new entry,
	 * expand the table if necessary (and this changes the resulting
	 * bucket chain).
	 */
	//if (t->numEntries >= rebuildLimit * t->size)
	//	RebuildTable(t);

	//e = malloc(sizeof(*e) + keylen);
	//e = malloc(sizeof(*e));
	//printf("3.1\n");
	hp = &t->bucketPtr[entry_hash_value & t->mask];
	if(*hp == NULL){
		//printf("3.2\n");
		*hp = e = malloc(sizeof(*e));
		e->left = NULL;
		e->right = NULL;
		e->m_key = m_key;
		e->packet_count = 1;
		e->byte_count = byte_count_of_arriving_entry; //OS_M_PKTLEN(PKT2MBUF(pkt)); //OS_M_PKTLEN(pkt->mbuf);
		e->create_time = get_current_time();
		e->update_time = e->create_time;
		e->check_updated_entry = 0; //to mark this as brand new entry.
		e->namehash = entry_hash_value; //hash_value;
		t->numEntries++;
		//printf("3.3\n");
		return e;
	}
	//printf("3.4\n");
	e = insert_binary(*hp, byte_count_of_arriving_entry, m_key, entry_hash_value);
	t->numEntries++;
	//printf("3.5\n");
	//e->next = *hp;
	//*hp = e;

	//Fill up data of monitoring entry
	//e->m_key = m_key;
	//e->packet_count = 1;
	//e->byte_count = byte_count_of_arriving_entry; //OS_M_PKTLEN(PKT2MBUF(pkt)); //OS_M_PKTLEN(pkt->mbuf);
	//e->create_time = get_current_time();
	//e->update_time = e->create_time;
	//
	//e->check_updated_entry = 0; //to mark this as brand new entry.

	//e->namehash = h; //hash_value;
	//strcpy(e->name, p); //key);


	if (newPtr != NULL)
		*newPtr = true;
	return e;
}

struct Hash_Entry *
HashTable_Add_Entry_From_Controller(struct Hash_Table *t, struct m_key *m_key, const char *key, bool *newPtr)
{
	return NULL;  //testing, delete this when uncommenting below code

	/*	Hash_Entry *e;
	unsigned int h;
	const char *p;
	int keylen;
	struct Hash_Entry **hp;
	unsigned int hash_value;

	/*
	 * Hash the key.  As a side effect, save the length (strlen) of the
	 * key in case we need to create the entry.
	 *

	for (h = 0, p = key; *p;)
		h = (h << 5) - h + *p++;
	keylen = p - key;
	p = key;

	hash_value = h & t->mask; //m_hash(key, t->size);

	//check if m_entry already existed in HashTable
	for (e = t->bucketPtr[h & t->mask]; e != NULL; e = e->next) {
		if (e->namehash == h && strcmp(e->name, p) == 0) {
			if (newPtr != NULL)
				*newPtr = false;
			return (e);
		}
	}

	/*
	 * The desired entry isn't there.  Before allocating a new entry,
	 * expand the table if necessary (and this changes the resulting
	 * bucket chain).
	 *
	if (t->numEntries >= rebuildLimit * t->size)
		RebuildTable(t);

	e = malloc(sizeof(*e) + keylen);
	hp = &t->bucketPtr[hash_value];
	e->next = *hp;
	*hp = e;

	//Fill up data of monitoring entry
	e->m_key = m_key;
	e->packet_count = 0;
	e->byte_count = 0;
	e->create_time = get_current_time();
	e->update_time = e->create_time;
	//

	e->check_updated_entry = 0; //to mark it as a new entry

	e->namehash = h; //hash_value;
	strcpy(e->name, p); //key);
	t->numEntries++;

	if (newPtr != NULL)
		*newPtr = true;
	return e;
	*/
}

/*
 *---------------------------------------------------------
 *
 * Hash_DeleteEntry --
 *
 * 	Delete the given hash table entry and free memory associated with
 *	it.
 *
 * Results:
 *	None.
 *
 * Side Effects:
 *	Hash chain that entry lives in is modified and memory is freed.
 *
 *---------------------------------------------------------
 */

void HashTable_Find_And_Delete_Entry(struct Hash_Table *t, char *key)
{
	//printf("checkpoint 1 \n");
/*	Hash_Entry *e, *tmp, **hp;
	unsigned int h;
	const char *p;
	unsigned int hash_value;

	for (h = 0, p = key; *p;)
		h = (h << 5) - h + *p++;
	p = key;
	hash_value = h & t->mask;  // m_hash(key, t->size);
	for (hp = &t->bucketPtr[hash_value]; (e = *hp) != NULL; hp = &e->next){
		//If found entry, DELETE the entry
		if (e->namehash == h && strcmp(e->name, p) == 0){
			*hp = e->next;
			free(e);
			t->numEntries--;
			//printf("Deleted m_entry: %s", *m_key);
			return;
		}
	}
	return NULL;
*/
}


void
HashTable_Delete_Entry(struct Hash_Table *t, struct Hash_Entry *e)
{
/*	Hash_Entry **hp, *p;

	if (e == NULL)
		return;
	for (hp = &t->bucketPtr[e->namehash & t->mask];
	     (p = *hp) != NULL; hp = &p->next) {
		if (p == e) {
			*hp = p->next;
			free(p);
			t->numEntries--;
			return;
		}
	}
	write(STDERR_FILENO, "bad call to Hash_DeleteEntry\n", 29);
	abort();
	*/
}

/*
 *---------------------------------------------------------
 *
 * Hash_EnumFirst --
 *	This procedure sets things up for a complete search
 *	of all entries recorded in the hash table.
 *
 * Results:
 *	The return value is the address of the first entry in
 *	the hash table, or NULL if the table is empty.
 *
 * Side Effects:
 *	The information in searchPtr is initialized so that successive
 *	calls to Hash_Next will return successive HashEntry's
 *	from the table.
 *
 *---------------------------------------------------------
 */

struct Hash_Entry *
Hash_EnumFirst(struct Hash_Table *t, struct Hash_Search *searchPtr)
{
	return NULL; //testing, remove this when uncommenting below code


/*	searchPtr->tablePtr = t;
	searchPtr->nextIndex = 0;
	searchPtr->hashEntryPtr = NULL;
	return (Hash_EnumNext(searchPtr));
*/
}

/*
 *---------------------------------------------------------
 *
 * Hash_EnumNext --
 *    This procedure returns successive entries in the hash table.
 *
 * Results:
 *    The return value is a pointer to the next HashEntry
 *    in the table, or NULL when the end of the table is
 *    reached.
 *
 * Side Effects:
 *    The information in searchPtr is modified to advance to the
 *    next entry.
 *
 *---------------------------------------------------------
 */
struct Hash_Entry *
Hash_EnumNext(struct Hash_Search *searchPtr)
{
	return NULL; //testing, remove this when uncommenting below code

/*	struct Hash_Entry *e;
	const Hash_Table *t = searchPtr->tablePtr;


	 //The hashEntryPtr field points to the most recently returned
	 //entry, or is NULL if we are starting up.  If not NULL, we have
	 //to start at the next one in the chain.

	e = searchPtr->hashEntryPtr;
	if (e != NULL)
		e = e->next;

	 //If the chain ran out, or if we are starting up, we need to
	 //find the next nonempty chain.

	while (e == NULL) {
		if (searchPtr->nextIndex >= t->size)
			return (NULL);
		e = t->bucketPtr[searchPtr->nextIndex++];
	}
	searchPtr->hashEntryPtr = e;
	return (e);
*/
}


void printHashEntry(struct Hash_Entry *e){
	printf("srcIP= %d.%d.%d.%d",(e->m_key->srcIp & 0xFF), ((e->m_key->srcIp >> 8) & 0xFF),
			((e->m_key->srcIp >> 16) & 0xFF),((e->m_key->srcIp >> 24) & 0xFF));
	printf("dstIP= %d.%d.%d.%d",(e->m_key->dstIp & 0xFF), ((e->m_key->dstIp >> 8) & 0xFF),
				((e->m_key->dstIp >> 16) & 0xFF),((e->m_key->dstIp >> 24) & 0xFF));
	printf(", %d", e->m_key->proto);
	printf(", (%u", e->packet_count);
	printf(", %u]\n",e->byte_count);
}

void printHashTable(struct Hash_Table *t){
	/*
	struct Hash_Search *search_Ptr;
	struct Hash_Entry *e;
	search_Ptr = (struct Hash_Search *)calloc(1, sizeof(struct Hash_Search));
	if (search_Ptr == NULL) {
	    return;
	}
	e = Hash_EnumFirst(t, search_Ptr);
	if(e != NULL)
		printHashEntry(e);
	while(e != NULL){
		e = Hash_EnumNext(search_Ptr);
		if(e != NULL)
				printHashEntry(e);
	}
	*/
}

/*
 *---------------------------------------------------------
 *
 * RebuildTable --
 *	This local routine makes a new hash table that
 *	is larger than the old one.
 *
 * Results:
 * 	None.
 *
 * Side Effects:
 *	The entire hash table is moved, so any bucket numbers
 *	from the old table are invalid.
 *
 *---------------------------------------------------------
 */
/*
static void
RebuildTable(struct Hash_Table *t)
{
	Hash_Entry *e, *next = NULL, **hp, **xp;
	int i, mask;
        Hash_Entry **oldhp;
	int oldsize;

	oldhp = t->bucketPtr;
	oldsize = i = t->size;
	i <<= 1;
	t->size = i;
	t->mask = mask = i - 1;
	t->bucketPtr = hp = (struct Hash_Entry *)calloc(1, sizeof(struct Hash_Entry)*i); //emalloc(sizeof(*hp) * i);
	while (--i >= 0)
		*hp++ = NULL;
	for (hp = oldhp, i = oldsize; --i >= 0;) {
		for (e = *hp++; e != NULL; e = next) {
			next = e->next;
			xp = &t->bucketPtr[e->namehash & mask];
			e->next = *xp;
			*xp = e;
		}
	}
	free(oldhp);
	printf("Current Table Size: %d\n", oldsize);
	printf("RE-BUILT Hash Table\n");
	printf("NEW table size: %d\n", t->size);
}
*/
