/*
 * monitoringdb.c
 *
 *  Created on: Aug 26, 2015
 *      Author: thien
 */
/*
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
*/

#include <openflow.h>
#include "openflow13.h"

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
//#include "pcap.h"
#include "City.h"
#include "murmurhash3.h"

//#include "stdio.h"
#include "lagopus/monitoringdb.h"
//#include "lagopus/monitoring_hash_table.h"
//#include "../agent/sdnmon_communication_apis.h"


/*static void
m_entry_free(struct m_entry *m_entry) {
  free(m_entry);
}
*/

/*static struct m_table *
m_table_alloc(uint8_t m_table_id) {
  int i;
  struct m_table *m_table;

  m_table = (struct m_table *)calloc(1, sizeof(struct m_table));
  if (m_table == NULL) {
    return NULL;
  }

  m_table->m_table_id = m_table_id;
  //for (i = 0; i < MAX_FLOWS; i++) {
    //m_table->m_entries[i].nm_entry = 0;
    //m_table->m_entries[i].m_entries = NULL;
    m_table->nm_entry = 0;
    m_table->m_entries = NULL;
  //}

  return m_table;
}
*/

/*static struct m_table *m_table_alloc() {
  int i;
  struct m_table *m_table;

  m_table = (struct m_table *)calloc(1, sizeof(struct m_table));
  if (m_table == NULL) {
    return NULL;
  }

  m_table->nm_entry = 0;
  m_table->m_entries = NULL;

  return m_table;
}
*/

/*static void
m_table_free(struct m_table *m_table) {
  struct m_entry **m_entries;
  int nm_entry, i, j;

  m_entries = m_table->m_entries;
  nm_entry = m_table->nm_entry;

  for (i = 0; i < nm_entry; i++) {
	  m_entry_free(m_entries[i]);
  }
  free(m_table);
}*/


/*struct monitoringdb *
monitoringdb_alloc(uint8_t initial_m_table_size){
	  struct monitoringdb *monitoringdb;
	  size_t table_index_size;
	  uint8_t i;

	  // Allocate monitoringdb. /
	  monitoringdb = (struct monitoringdb *)calloc(1, sizeof(struct monitoringdb));
	  if (monitoringdb == NULL) {
	    return NULL;
	  }

	  // Allocate table index. /
	  table_index_size = sizeof(struct m_table *) * (MONITORINGDB_TABLE_SIZE_MAX + 1);
	  monitoringdb->m_tables = (struct m_table **)calloc(1, table_index_size);
	  if (monitoringdb->m_tables == NULL) {
		  monitoringdb_free(monitoringdb);
	    return NULL;
	  }

	  // Allocate tables. /
	  for (i = 0; i < initial_m_table_size; i++) {
		monitoringdb->m_tables[i] = m_table_alloc(i);
	    if (monitoringdb->m_tables[i] == NULL) {
	    	monitoringdb_free(monitoringdb);
	      return NULL;
	    }
	  }

	  // Set table size. /
	  monitoringdb->m_table_size = MONITORINGDB_TABLE_SIZE_MAX;

	  // Initialize read write lock. /
	  monitoringdb_lock_init(NULL);

	  return monitoringdb;
}
*/

struct monitoringdb *monitoringdb_alloc(){
	  struct monitoringdb *monitoringdb;
	  int numBuckets = 4000;
	  //uint8_t i;

	  // Allocate monitoringdb. /
	  monitoringdb = (struct monitoringdb *)calloc(1, sizeof(struct monitoringdb));
	  if (monitoringdb == NULL) {
		DP_PRINT("DP_PRINT-Error: MONITORING DB calloc FAILED!\n");
		printf("prinf-Error: MONITORING DB calloc FAILED!");
	    return NULL;
	  }

	  // Allocate table index. /
/*	  monitoringdb->m_table = m_table_alloc();
	  if (monitoringdb->m_table == NULL) {
		  monitoringdb_free(monitoringdb);
		  return NULL;
	  }
*/
	  monitoringdb->hash_table = allocHashTable(numBuckets); //table size = 2 luy thua 12 = 4096 //allocHashTable(MONITORINGDB_TABLE_SIZE_MAX);
	  	  if (monitoringdb->hash_table == NULL) {
	  		  monitoringdb_free(monitoringdb);
	  		  return NULL;
	  	  }


	  // Initialize read write lock. /
	  //monitoringdb_lock_init(NULL);

	 if(monitoringdb != NULL) {
		printf("printf - MONITORING DB alloc SUCCESS!");
		DP_PRINT("DP_PRINT-Error: MONITORING DB calloc SUCCESS!\n");}
	else {
		printf("prinf - Error: MONITORING DB alloc FAILED!");
		DP_PRINT("DP_PRINT-Error: MONITORING DB calloc FAILED!\n");}

	 monitoringdb->sampling_ratio = 0.5;
	 monitoringdb->n_stats = 5;
	 monitoringdb->query_time_interval = 20.0;
	 monitoringdb->overflow_notification_threshold = 100000;
	 monitoringdb->n_flows = 0;
	 monitoringdb->n_bloom_members = 0;
	 monitoringdb->n_m_entries = 0;
	 monitoringdb->flow_count = 0;

	  return monitoringdb;
}


/*void
monitoringdb_free(struct monitoringdb *monitoringdb){
	  int i;

	  // Free table index. /
	  if (monitoringdb->m_tables != NULL) {
	    for (i = 0; i < monitoringdb->m_table_size; i++) {
	      if (monitoringdb->m_tables[i]) {
	        m_table_free(monitoringdb->m_tables[i]);
	        monitoringdb->m_tables[i] = NULL;
	      }
	    }
	    free(monitoringdb->m_tables);
	    monitoringdb->m_tables = NULL;
	  }

	  // Free monitoringdb. /
	  free(monitoringdb);
}
*/

void
monitoringdb_free(struct monitoringdb *monitoringdb){
      if (monitoringdb->hash_table != NULL) {
        Hash_DeleteTable(monitoringdb->hash_table);
        monitoringdb->hash_table = NULL;
      }
	  // Free monitoringdb.
	  free(monitoringdb);
}

struct m_key *
extract_m_key_from_packet(struct lagopus_packet *pkt){

	//IPV4_HDR *ipv4_hdr;
//	printf("\nextract_m_key_from_packet(...) called\n");
	//IPV4_HDR *ipv4_hdr;
	struct m_key *key;
	key = (struct m_key *)calloc(1, sizeof(struct m_key));
//	printf("Thien checkpoint 002\n");
	if (key == NULL) {
	    return NULL;
	}
/*	key->srcIp=NULL;
	key->dstIp=NULL;*/

	//only process ipv4 packet
	if(pkt->ipv4 == NULL){
		//printf("Not IPv4 packet: ignored\n");
		return NULL;
	}

	key->srcIp=pkt->ipv4->ip_src.s_addr;
//			printf("Thien checkpoint 002.1\n");

	key->dstIp=pkt->ipv4->ip_dst.s_addr;
//			printf("Thien checkpoint 002.2\n");

	key->proto=IPV4_PROTO(pkt->ipv4);
			//printf("Thien checkpoint 002.3\n");
	key->srcPort = 65535; //65535 means srcPort, dstPort has NULL value
	key->dstPort = 65535;

	//only process ipv4: TCP/UDP/SCTP

	if(key->proto == 1){
		//printf("ICMP packet\n");
		key->srcPort = 65535;
		key->dstPort = 65535;
		return key;
	}
	if(key->proto == 6){
		//printf("TCP packet\n");
		key->srcPort=TCP_SPORT(pkt->tcp);
		key->dstPort=TCP_DPORT(pkt->tcp);
		return key;
	}
	if(key->proto == 17){
		//printf("UDP packet\n");
		key->srcPort=UDP_SPORT(pkt->udp);
		key->dstPort=UDP_DPORT(pkt->udp);
		return key;
	}

//	if(pkt->tcp != NULL){
//		printf("TCP packet\n");
//		key->srcPort=TCP_SPORT(pkt->tcp);
//		key->dstPort=TCP_DPORT(pkt->tcp);
//		return key;
//	} else{
//		if(pkt->udp != NULL){
//			printf("UDP packet\n");
//			key->srcPort=UDP_SPORT(pkt->udp);
//			key->dstPort=UDP_DPORT(pkt->udp);
//			return key;
//		} else{
//			if(pkt->sctp != NULL){
//				printf("SCTP packet\n");
//				key->srcPort=SCTP_SPORT(pkt->sctp);
//				key->dstPort=SCTP_DPORT(pkt->sctp);
//				return key;
//			}
//			else{
//				if(pkt->icmp != NULL){
//					printf("ICMP packet\n");
//					key->srcPort=65535;
//					key->dstPort=65535;
//					return key;
//				}
//			}
//		}
//	}
//	printf("Thien checkpoint 003\n");

	//testing
/*	printf("[srcIp = %s", inet_ntoa(key->srcIp));
	printf(", dstIp = %s", inet_ntoa(key->dstIp));
	printf(", proto = %d", key->proto);

	if(key->srcPort != NULL){
		printf(", tcpSrcPort = %" PRIu16 "", key->srcPort);  //TCP_SPORT(pkt->tcp));
	}
	if(key->dstPort != NULL){
		printf(", tcpDstPort = %" PRIu16 "]\n", key->dstPort); //TCP_DPORT(pkt->tcp));//
	}
*/
	//ipv4_hdr = pkt->ipv4;
	//ipv4_hdr = pkt->ipv4;
	//printf("srcIp: "PRIu32"\n", IPV4_SRC(ipv4_hdr)); //key->srcIp = IPV4_SRC(pkt->ipv4);  printf("srcIp: %pI4"+key->srcIp);
	//printf("srcIp: "PRIu32"\n", ipv4_hdr->ip_src.s_addr);
//	printf("Thien checkpoint 004\n");


//bo may ham nay di, gan m_key bang cac bien khac cua lagopus_packet xem sao???




//	printf("srcPort: %d", TCP_SPORT(pkt->tcp));//key->srcPort = TCP_SPORT(pkt->tcp); printf("srcPort: "+key->srcPort);
//	printf("Thien checkpoint 005\n");

//	printf("Extracted m_key: \n");
//	printf("-srcIp: %s, ", inet_ntoa(pkt->ipv4->ip_src));
//	printf("Thien checkpoint 006\n");


	//	printf("dstPort: %d", TCP_DPORT(pkt->tcp));//key->dstPort = TCP_DPORT(pkt->tcp); printf("dstPort: "+key->dstPort);
//	printf("dstIp: %s, ", inet_ntoa(pkt->ipv4->ip_dst)); //%pI4",IPV4_DST(ipv4_hdr));//key->dstIp = IPV4_DST(pkt->ipv4); printf("dstIp: %pI4"+key->dstIp);
//	printf("Thien checkpoint 007\n");
//	printf("proto: %d\n", IPV4_PROTO(pkt->ipv4));//key->proto = IPV4_PROTO(pkt->ipv4);/*pkt->proto;


/*
	printf("proto: %u", key->proto);
	printf(" table_id: %u", pkt->table_id);
	printf(" flag: %zu", pkt->flags);
*/

//	printf("Thien checkpoint 008\n");
	return NULL;
}

/*static lagopus_result_t
m_entry_add_sub(struct m_entry *m_entry, struct m_table *m_table) {
  lagopus_result_t ret;
  //struct m_entry **m_entries;

  //m_entries = m_table->m_entries;
  ret = LAGOPUS_RESULT_OK;
  m_table->m_entries = realloc(m_table->m_entries,
                         (size_t)(m_table->nm_entry + 1) * sizeof(struct m_entry *));
  if (m_table->m_entries == NULL) {
    ret = LAGOPUS_RESULT_NO_MEMORY;
    goto out;
  }

  /* Insert m_entry into the point. /
  m_table->m_entries[m_table->nm_entry] = m_entry;
  m_table->nm_entry++;
out:
  return ret;
}
*/

/*lagopus_result_t
monitoringdb_m_entry_add(struct monitoringdb *mdb, uint8_t m_table_id, struct lagopus_packet *pkt){
	struct m_table *m_table;
	lagopus_result_t ret = LAGOPUS_RESULT_OK;
	struct m_entry *m_entry;
	struct m_key m_key;
	m_key = extract_m_key_from_packet(pkt);


	  // Write lock the flowdb. /
	  monitoringdb_wrlock(mdb);

	  // Get table. /
	  m_table = m_table_lookup(mdb, m_table_id);
	  if (m_table == NULL) {
	    ret = LAGOPUS_RESULT_OFP_ERROR;
	    goto out;
	  }

	  // Allocate a new m_entry. /
	  ret = m_entry_alloc(&m_entry);
	  if (m_entry == NULL) {
		  ret = LAGOPUS_RESULT_OFP_ERROR;
		  goto out;
	  }

	  ret = m_entry_add_sub(m_entry, &m_table);

	out:
	  // Unlock the flowdb then return result. /
	  monitoringdb_wrunlock(mdb);
	  return ret;
}
*/

/*static struct m_entry  *m_entry_alloc(struct lagopus_packet *pkt, struct m_key *key, int n_stats){
	struct m_entry *entry;
	struct statistics *stats;
	//lagopus_result_t ret = LAGOPUS_RESULT_OK;

	entry = (struct m_entry *)calloc(1, sizeof(struct m_entry));
	if (entry == NULL) {
	    return NULL;
	}
	entry->m_key = key;
	entry->stats_list = calloc(1, (size_t) n_stats * sizeof(struct statistics *));
	entry->n_stats = n_stats;

	for(int i = 0; i< entry->n_stats; i++){
		stats = (struct statistics *)calloc(1, sizeof(struct statistics));
		if (stats == NULL) {
			return NULL;
		}
		stats->byte_count = 0;
		stats->packet_count = 0;
		entry->stats_list[i] = stats;
	}
	stats->packet_count++;
	stats->byte_count += OS_M_PKTLEN(pkt->mbuf);
	entry->stats_list[0] = stats;

	entry->create_time = get_current_time();
	entry->update_time = entry->create_time;
	return entry;
}*/


/*n_stats: number of stats item in statistics list of the m_entry that will be added
  */
lagopus_result_t
monitoringdb_m_entry_add(struct monitoringdb *mdb, struct lagopus_packet *pkt, struct m_key *key, char *m_key_str){

	lagopus_result_t ret = LAGOPUS_RESULT_OK;
	bool *newPtr;
	newPtr = false;
	Hash_Entry *e;
	e = HashTable_Add_Entry(mdb->hash_table, pkt, key, m_key_str, newPtr);
	if(e == NULL) //(newPtr == false)
		ret = LAGOPUS_RESULT_OFP_ERROR;

	mdb->n_m_entries = mdb->hash_table->numEntries;
	printf("monitoringdb.c-monitoringdb_m_entry_add() - mdb->n_m_entries= %d ", mdb->n_m_entries);
	//printf(" %s\n",m_key_str);

	return ret;
}

lagopus_result_t
insert_m_entry_from_controller(struct monitoringdb *mdb, struct m_key *key){

	lagopus_result_t ret = LAGOPUS_RESULT_OK;
	bool *newPtr;
	newPtr = false;
	Hash_Entry *e;
	char *m_key_str=NULL;

	m_key_str = m_key_to_string(key);
	e = HashTable_Add_Entry_From_Controller(mdb->hash_table, key, m_key_str, newPtr);
	if(e == NULL) //(newPtr == false)
		ret = LAGOPUS_RESULT_OFP_ERROR;

	//mdb->n_m_entries++;  // => SAI, khi m_entry da ton tai trong HashTable (ko add them entry), gia n_m_entries van tang->sai => SUA LAI SAU (2017-01-13)
	mdb->n_m_entries = mdb->hash_table->numEntries;
	printf("monitoringdb.c-insert_m_entry_from_controller()- mdb->n_m_entries= %d ", mdb->n_m_entries);
	//printf(" %s\n",m_key_str);

	return ret;
}

lagopus_result_t
remove_m_entry_from_controller(struct monitoringdb *mdb, struct m_key *key){

	lagopus_result_t ret = LAGOPUS_RESULT_OK;
	bool *newPtr;
	newPtr = false;
	Hash_Entry *e;
	char *m_key_str=NULL;

	m_key_str = m_key_to_string(key);
	HashTable_Find_And_Delete_Entry(mdb->hash_table, m_key_str);
//	if(e == NULL) //(newPtr == false)
//		ret = LAGOPUS_RESULT_OFP_ERROR;

	//mdb->n_m_entries--;
	mdb->n_m_entries = mdb->hash_table->numEntries;
	printf("monitoringdb.c-remove_m_entry_from_controller() - mdb->n_m_entries= %d ", mdb->n_m_entries);
	//printf(" %s\n",m_key_str);

	return ret;
}

lagopus_result_t
reset_m_table_from_controller(struct monitoringdb *mdb){
	lagopus_result_t ret = LAGOPUS_RESULT_OK;
	HashTable_Reset_Table(mdb->hash_table);

	return ret;
}

//Unused
/*static bool
m_entry_compare(struct m_entry *e1, struct m_entry *e2) {
  if (e1 != e2) {
    return false;
  }
  return true;
}
*/

/*static lagopus_result_t
m_table_m_entry_delete(struct m_table *m_table, struct m_entry *m_entry){
	lagopus_result_t ret;
	int i;

	ret = LAGOPUS_RESULT_OK;
    for (i = 0; i < m_table->nm_entry; i++) {
      if (m_entry_compare(m_entry, m_table->m_entries[i]) == true) {
        m_entry_free(m_table->m_entries[i]);
        m_table->nm_entry--;
        if (i < m_table->nm_entry) {
          memmove(&m_table->m_entries[i], &m_table->m_entries[i + 1],
                  sizeof(struct m_entry *) *
                  (unsigned int)(m_table->nm_entry - i));
        }
        break;
      }
    }
    return ret;
}
*/

/*lagopus_result_t
monitoringdb_m_entry_delete(struct monitoringdb *mdb, struct m_entry *m_entry){
 
  lagopus_result_t ret;
  struct m_table *m_table;

  /* Write lock the mdb. /
  monitoringdb_wrlock(mdb);

  m_table = mdb->m_table;
  if (m_table == NULL) {
        ret = LAGOPUS_RESULT_OFP_ERROR;
        goto out;
  }

  m_table_m_entry_delete(m_table, m_entry);
  mdb->m_table = m_table;
  /* Unlock the mdb and return result. /
out:
  monitoringdb_wrunlock(mdb);
  return ret;
}
*/

/*static bool m_key_compare(struct m_key *key1, struct m_key *key2){
/*	if(key1 != key2){
		return false;
	}
	return true;/
	if(key1->srcIp.s_addr == key2->srcIp.s_addr &&
			key1->dstIp.s_addr == key2->dstIp.s_addr &&
			key1->proto == key2->proto){
//		printf("m_key_compare: m_key1 == m_key2\n");
		return true;
	}
//	printf("m_key_compare: m_key1 != m_key2\n");
	return false;
}
*/

//Unused function
/*struct m_entry *monitoringdb_lookup_m_entry_by_key(struct monitoringdb *mdb, struct m_key *m_key){
  struct m_key *key;
  int i;

/*		  printf("Looking up m_entry by m_key...\n");*/
/*
		  if(mdb == NULL) printf("mdb == NULL\n");
		  else printf("mdb != NULL\n");
*/

/*		  printf("m_key --- srcIp: %s", inet_ntoa(m_key->srcIp));
		      				printf(" dstIp: %s", inet_ntoa(m_key->dstIp));
		      				printf(" proto: %d\n", m_key->proto);/

  for (i = 0; i < mdb->m_table->nm_entry; i++) {
    key = mdb->m_table->m_entries[i]->m_key;
//    				printf(" m_entry[%d]: ", i);
//    				printf(" srcIp: %s ", inet_ntoa(key->srcIp));
//    				printf(" dstIp: %s ", inet_ntoa(key->dstIp));
//    				printf(" proto: %d\n", key->proto);
	  if (m_key_compare(m_key, key) == true) {
		  	  	  	  //printf("m_key MATCHED with an entry in Monitoring database.\n");
		  return mdb->m_table->m_entries[i];
	  }
  }
  	  	  	  	  	  //printf("m_key NOT matched with any entry in Monitoring database.\n");
  return NULL;
}
*/

//Unused function
/*struct m_entry *monitoringdb_lookup_m_entry_by_packet(struct monitoringdb *mdb, struct lagopus_packet *pkt){
	struct m_key *m_key;
	m_key = extract_m_key_from_packet(pkt);
	return monitoringdb_lookup_m_entry_by_key(mdb, m_key);
}
*/

/*struct m_entry *monitoringdb_lookup_m_entry(struct monitoringdb *mdb, struct m_key *m_key){
	struct m_entry *entry;
	entry = m_table_lookup_m_entry_by_packet(mdb->m_table, m_key);
	return entry;
}
*/
struct Hash_Entry *monitoringdb_lookup_and_update_m_entry(struct monitoringdb *mdb, char *m_key_str, struct lagopus_packet *pkt){
	return HashTable_Find_And_Update_Entry(mdb->hash_table, pkt, m_key_str);
}

static void copy_entry_stats(struct m_entry_stats *m_entry_stats, struct Hash_Entry *e){

	//copy stats from entry to m_entry_stats, all passed by values (not by pointers)
	m_entry_stats->stats.packet_count = e->packet_count;
	m_entry_stats->stats.byte_count = e->byte_count;

#define COPY_M_KEY(member) m_entry_stats->m_key.member = e->m_key->member;
	COPY_M_KEY(srcIp);
	COPY_M_KEY(dstIp);
	COPY_M_KEY(proto);
	if(e->m_key->srcPort != NULL){
		COPY_M_KEY(srcPort);
	}else{
		m_entry_stats->m_key.srcPort = NULL;
	}
	if(e->m_key->dstPort != NULL){
		COPY_M_KEY(dstPort);
	}else{
		m_entry_stats->m_key.dstPort = NULL;
	}
#undef COPY_M_KEY
}

static lagopus_result_t
hashTable_Get_Entry_Stats(struct Hash_Table *t, struct m_entry_stats_list *m_entry_stats_list){

	struct m_entry_stats *m_entry_stats;
	lagopus_result_t rv;

	rv = LAGOPUS_RESULT_OK;
	struct Hash_Search *search_Ptr;
	struct Hash_Entry *e;
	search_Ptr = (struct Hash_Search *)calloc(1, sizeof(struct Hash_Search));
	if (search_Ptr == NULL) {
		goto out;
	}
	e = Hash_EnumFirst(t, search_Ptr);
	if(e != NULL){
		m_entry_stats = calloc(1, sizeof(struct m_entry_stats));
		if (m_entry_stats == NULL) {
		        goto out;
		}
		//copy stats from hash entry to m_entry_stats
		copy_entry_stats(m_entry_stats, e);
	    /* and link to list. */
	    TAILQ_INSERT_TAIL(m_entry_stats_list, m_entry_stats, entry);
	}
	while(e != NULL){
		e = Hash_EnumNext(search_Ptr);
		if(e != NULL){
			m_entry_stats = calloc(1, sizeof(struct m_entry_stats));
			if (m_entry_stats == NULL) {
			        goto out;
			}
			//copy stats from hash entry to m_entry_stats
			copy_entry_stats(m_entry_stats, e);
		    /* and link to list. */
		    TAILQ_INSERT_TAIL(m_entry_stats_list, m_entry_stats, entry);
		}
	}
out:
	return rv;
}


lagopus_result_t monitoringdb_m_entry_stats(struct monitoringdb *mdb,
		struct ofp_experimenter_multipart_header *exper_req,
		struct m_entry_stats_list *m_entry_stats_list,
		struct ofp_error *error){

	lagopus_result_t rv;

	/* Write lock the monitoringdb. */
	//monitoringdb_wrlock(mdb);
	rv = hashTable_Get_Entry_Stats(mdb->hash_table, m_entry_stats_list); //used parameters: exper_req, error
	//monitoringdb_wrunlock(mdb);
	return rv;

}
	  /*	  double update_time_interval =  mdb->query_time_interval/mdb->n_stats;
	  struct timespec current_time = get_current_time();
	  printf("update_time_interval == %f\n", update_time_interval);
	  printf("current time: %ld", current_time.tv_sec);
	  for (i = 0; i < mdb->m_table->nm_entry; i++) {
	    key = mdb->m_table->m_entries[i]->m_key;
		  if (m_key_compare(m_key, key) == true) {
			  //update statistics list only when the time interval between current time and last update is >= update_time_interval
/*			  printf("update_time == %ld\n", mdb->m_table->m_entries[i]->update_time.tv_sec);
			  printf("entry %i ", i);
			  printf("->n_stats = %i\n", mdb->m_table->m_entries[i]->n_stats);*/
/*
			  if(current_time.tv_sec - mdb->m_table->m_entries[i]->update_time.tv_sec > update_time_interval){
				  printf("         ***** Updating stats_list...\n");
				  //update statistics list, from item 1 to item n_stats
				  for(int j = mdb->m_table->m_entries[i]->n_stats - 1; j > 0; --j){
					  printf("stats_list-%i ", j);
					  mdb->m_table->m_entries[i]->stats_list[j]->packet_count = mdb->m_table->m_entries[i]->stats_list[j-1]->packet_count;
					  mdb->m_table->m_entries[i]->stats_list[j]->byte_count = mdb->m_table->m_entries[i]->stats_list[j-1]->byte_count;
				  }
				  mdb->m_table->m_entries[i]->update_time = current_time;
			  }

			  mdb->m_table->m_entries[i]->stats_list[0]->packet_count++;
			  mdb->m_table->m_entries[i]->stats_list[0]->byte_count += OS_M_PKTLEN(pkt->mbuf);
			  return mdb->m_table->m_entries[i];
		  }
	  }
	  return NULL;
	  */


//Unused function
/*static lagopus_result_t
m_table_m_entry_update_stats(struct monitoringdb *mdb, struct m_key *m_key, struct lagopus_packet *pkt){
	  
	 // struct m_table *m_table;
	  struct m_key *key;
	  int i;
	  lagopus_result_t ret;
	  double update_time_interval =  mdb->query_time_interval/mdb->n_stats;
	  struct timespec current_time = get_current_time();
/*	  printf("update_time_interval == %f\n", update_time_interval);
	  printf("current time: %ld", current_time.tv_sec);/

	  ret = LAGOPUS_RESULT_OFP_ERROR;
	  for (i = 0; i < mdb->m_table->nm_entry; i++) {
	    key = mdb->m_table->m_entries[i]->m_key;
		  if (m_key_compare(m_key, key) == true) {
			  //update statistics list only when the time interval between current time and last update is >= update_time_interval
/*			  printf("update_time == %ld\n", mdb->m_table->m_entries[i]->update_time.tv_sec);
			  printf("entry %i ", i);
			  printf("->n_stats = %i\n", mdb->m_table->m_entries[i]->n_stats);*/
/*
			  if(current_time.tv_sec - mdb->m_table->m_entries[i]->update_time.tv_sec > update_time_interval){
				  printf("         ***** Updating stats_list...\n");
				  //update statistics list, from item 1 to item n_stats
				  for(int j = mdb->m_table->m_entries[i]->n_stats - 1; j > 0; --j){
					  printf("stats_list-%i ", j);
					  mdb->m_table->m_entries[i]->stats_list[j]->packet_count = mdb->m_table->m_entries[i]->stats_list[j-1]->packet_count;
					  mdb->m_table->m_entries[i]->stats_list[j]->byte_count = mdb->m_table->m_entries[i]->stats_list[j-1]->byte_count;
				  }
				  mdb->m_table->m_entries[i]->update_time = current_time;
			  }
/


			  mdb->m_table->m_entries[i]->stats_list[0]->packet_count++;
			  mdb->m_table->m_entries[i]->stats_list[0]->byte_count += OS_M_PKTLEN(pkt->mbuf);
			  ret = LAGOPUS_RESULT_OK;

/*
			  printf("---++++ Stats UPDATED for m_entry: \n");
			  printf(" -m_key: srcIp: %s ", inet_ntoa(key->srcIp));
			      				printf(" dstIp: %s ", inet_ntoa(key->dstIp));
			      				printf(" proto: %d\n", key->proto);
			  printf(" -Packet count= %" PRIu64 "\n", mdb->m_table->m_entries[i]->stats_list[0]->packet_count);
			  printf(" -Byte count= %" PRIu64 "\n", mdb->m_table->m_entries[i]->stats_list[0]->byte_count);
/

			  return ret;
		  }
	  }
/*	  printf("Monitoring database: \n");
	  printf("{srcIP, dstIP, proto, packet count, byte count}\n");
	  for (i = 0; i < mdb->m_table->nm_entry; i++) {
	  	  	  	  	  printf(" m_entry[%d]: ", i);
	      				printf("{ %s, ", inet_ntoa(key->srcIp));
	      				printf(" dstIp: %s, ", inet_ntoa(key->dstIp));
	      				printf(" proto: %d, ", key->proto);
	      			  printf(" %" PRIu64 ", ", mdb->m_table->m_entries[i]->packet_count);
	      			  printf(" %" PRIu64 "\n", mdb->m_table->m_entries[i]->byte_count);
	  }/
	  return ret;
}
*/

/*lagopus_result_t
monitoringdb_m_entry_update_stats(struct monitoringdb *mdb, struct m_key *m_key, struct lagopus_packet *pkt){
	return m_table_m_entry_update_stats(mdb, m_key, pkt);
}
*/

/*char *m_key_to_string(struct m_key *m_key){

	printf("1\n");
	size_t buf_size = 0, offset = 0;
	char *buffer = NULL, *temp = NULL;
	uint32_t s_addr = (uint32_t) m_key->srcIp.s_addr;
	uint32_t d_addr = (uint32_t) m_key->dstIp.s_addr;
	uint8_t proto = (uint8_t) m_key->proto;

	printf("2\n");
	buffer = realloc(buffer, sizeof(uint32_t));
	if (buffer == NULL) {
	    exit(EXIT_FAILURE);
		//return NULL;
	}
	printf("3\n");
	buf_size = sizeof(uint32_t);
	for(size_t b = 0; b < sizeof(uint32_t); ++b) {
	    buffer[offset + b] = (s_addr >> b*8) & 0xFF;
	}
	offset += sizeof(uint32_t);
	printf("4\n");

	temp = realloc(buffer, buf_size + sizeof(uint32_t));
	if (temp == NULL) {
	    free(buffer);
	    exit(EXIT_FAILURE);
	}
	printf("5\n");
	buffer = temp;
	temp = NULL;
	buf_size += sizeof(uint32_t);
	printf("6\n");
	for(size_t b = 0; b < sizeof(uint32_t); ++b) {
	    buffer[offset + b] = (d_addr >> b*8) & 0xFF;
	}
	printf("7\n");
	offset += sizeof(uint32_t);
	printf("8\n");
	temp = realloc(buffer, buf_size + sizeof(uint8_t));
	if (temp == NULL) {
	    free(buffer);
	    exit(EXIT_FAILURE);
	}
	printf("9\n");
	buffer = temp;
	temp = NULL;
	buf_size += sizeof(uint8_t);
	for(size_t b = 0; b < sizeof(uint8_t); ++b) {
	    buffer[offset + b] = (proto >> b*8) & 0xFF;
	}
	printf("10\n");
	offset += sizeof(uint8_t);
	printf("11\n");
	printf("m_key string: ");
	for(int i = 0; i<buf_size; ++i)
		printf("%c", buffer[i]);
	printf("12\n");
	return buffer;
}*/

/*
char *m_key_to_string(struct m_key *m_key){

	//printf("m_key_to_string(...) called\n");
	char buf[13]; //13 bytes to store 104 bits (13 bytes) of m_key's 5-tuples
	buf[0] = (uint32_t) m_key->srcIp.s_addr >> 24;
	buf[1] = (uint32_t) m_key->srcIp.s_addr >> 16;
	buf[2] = (uint32_t) m_key->srcIp.s_addr >> 8;
	buf[3] = (uint32_t) m_key->srcIp.s_addr;

	buf[4] = (uint32_t) m_key->dstIp.s_addr >> 24;
	buf[5] = (uint32_t) m_key->srcIp.s_addr >> 16;
	buf[6] = (uint32_t) m_key->srcIp.s_addr >> 8;
	buf[7] = (uint32_t) m_key->srcIp.s_addr;

	buf[8] = m_key->proto;
	//printf("check 0003");

	if(m_key->srcPort != NULL){
		printf("m_key->srcPort != NULL");
		buf[9] = m_key->srcPort >> 8;
		buf[10] = m_key->srcPort;
	} else{
		printf("m_key->srcPort == NULL");
		buf[9] = 'x';
		buf[10] = 'x';
	}
	//printf("check 0004");
	if(m_key->dstPort != NULL){
		printf("m_key->dstPort != NULL");
		buf[11] = m_key->dstPort >> 8;
		buf[12] = m_key->dstPort;
	} else{
		printf("m_key->dstPort == NULL");
		buf[11] = 'x';
		buf[12] = 'x';
	}
	//printf("check 0005");
//	printf("\n Converted string m_key: ");
//	for(int i=0; i<13; i++){
//		printf(" %c", buf[i]);
//	}
	return buf;
}
*/
/*
char *m_key_to_string(struct m_key *m_key){ //, char *m_key_str){

	#define FIELD_WIDTH 108 //32bit + 32bit + 16bit + 16bit + 8bit + 4 '_'
	//size_t buf_size = 0, offset = 0;
	char str[1000]; //, *temp = NULL;

	printf("*m_key_to_string(...) called\n");

	strcpy(str, inet_ntoa(m_key->srcIp));

	strcat(str, inet_ntoa(m_key->dstIp));

	strcat(str, m_key->proto);

	if(m_key->srcPort != NULL){
		//printf("srcPort = %" PRIu16 " ", m_key->srcPort);
		strcat(str, m_key->srcPort);
	}
	if(m_key->dstPort != NULL){
		//printf("dstPort = %" PRIu16 "]\n", m_key->dstPort);
		strcat(str, m_key->dstPort);
	}

	return str;
}
*/


char *m_key_to_string(struct m_key *m_key){ //, char *m_key_str){

	size_t buf_size = 0, offset = 0;
	char *buffer;
	int n_char;

	//printf("*m_key_to_string(...) called\n");
	buffer = (char *)malloc(50);//FIELD_WIDTH); // one for the '\0'
	if (buffer == NULL) {
		exit(EXIT_FAILURE);
	}
	//buf_size = 1025; //FIELD_WIDTH + 1;
	n_char = sprintf(buffer, "%d.%d.%d.%d",((m_key->srcIp >> 24) & 0xFF),
			((m_key->srcIp >> 16) & 0xFF),((m_key->srcIp >> 8) & 0xFF),(m_key->srcIp & 0xFF)); // inet_ntoa(m_key->srcIp));
	//sprintf(buffer, "%0" STR(FIELD_WIDTH) PRIu32, s_addr);
	offset += n_char; // FIELD_WIDTH;//32;

	sprintf(buffer + offset, "_");
	n_char = sprintf(buffer + offset + 1, "%d.%d.%d.%d",((m_key->dstIp >> 24) & 0xFF),
			((m_key->dstIp >> 16) & 0xFF),((m_key->dstIp >> 8) & 0xFF),(m_key->dstIp & 0xFF));//inet_ntoa(m_key->dstIp));
	offset += n_char + 1; // FIELD_WIDTH + 1;//33;

	sprintf(buffer + offset, "_");
	n_char = sprintf(buffer + offset + 1, "%" PRIu8, m_key->proto);
	offset += n_char + 1; //FIELD_WIDTH + 1;//9;

	if(m_key->srcPort != NULL){
		//printf("srcPort = %" PRIu16 " ", m_key->srcPort);
		sprintf(buffer + offset, "_");
		n_char = sprintf(buffer + offset + 1, "%" PRIu16, m_key->srcPort);
		offset += n_char + 1; //FIELD_WIDTH + 1; //17;
	} else{
		sprintf(buffer + offset, "_x");
		offset += 2;
	}
	if(m_key->dstPort != NULL){
		//printf("dstPort = %" PRIu16 "]\n", m_key->dstPort);
		sprintf(buffer + offset, "_");
		n_char = sprintf(buffer + offset + 1, "%" PRIu16, m_key->dstPort);
		offset += n_char + 1; //FIELD_WIDTH + 1;//17;
	} else{
		sprintf(buffer + offset, "_x");
		offset += 2;
	}
	//sprintf(buffer + offset, "\0");
	return buffer;
}


/*
char *m_key_to_string(struct m_key *m_key){ //, char *m_key_str){
#define FIELD_WIDTH 13

//uint32_t s_addr = (uint32_t) m_key->srcIp.s_addr;
//uint32_t d_addr = (uint32_t) m_key->dstIp.s_addr;

size_t buf_size = 0, offset = 0;
char *buffer = NULL, *temp = NULL;
buffer = (char *)realloc(buffer, FIELD_WIDTH + 1); // one for the '\0'
if (buffer == NULL) {
    exit(EXIT_FAILURE);
}
buf_size = FIELD_WIDTH + 1;
sprintf(buffer, inet_ntoa(m_key->srcIp));
//sprintf(buffer, "%0" STR(FIELD_WIDTH) PRIu32, s_addr);
offset += FIELD_WIDTH;

temp = realloc(buffer, buf_size + FIELD_WIDTH);
if (temp == NULL) {
    free(buffer);
    exit(EXIT_FAILURE);
}
buffer = temp;
temp = NULL;
buf_size += FIELD_WIDTH + 1;
sprintf(buffer + offset, "_");
sprintf(buffer + offset + 1, inet_ntoa(m_key->dstIp));
offset += FIELD_WIDTH + 1;


temp = realloc(buffer, buf_size + FIELD_WIDTH);
if (temp == NULL) {
    free(buffer);
    exit(EXIT_FAILURE);
}
buffer = temp;
temp = NULL;
buf_size += FIELD_WIDTH + 1;
sprintf(buffer + offset, "_");
sprintf(buffer + offset + 1, "%d", m_key->proto);
offset += FIELD_WIDTH + 1;

/*
if(m_key->srcPort != NULL){
//	printf("m_key->srcPort != NULL\n");
	temp = realloc(buffer, buf_size + FIELD_WIDTH);
	if (temp == NULL) {
		free(buffer);
		exit(EXIT_FAILURE);
	}
	buffer = temp;
	temp = NULL;
	buf_size += FIELD_WIDTH + 1;
	sprintf(buffer + offset, "_");
	sprintf(buffer + offset + 1, "%" PRIu64 "", m_key->srcPort);
	offset += FIELD_WIDTH + 1;
}
//else{
//	printf("m_key->srcPort == NULL\n");
//}

if(m_key->dstPort != NULL){
//	printf("m_key->dstPort != NULL\n");
	temp = realloc(buffer, buf_size + FIELD_WIDTH);
	if (temp == NULL) {
		free(buffer);
		exit(EXIT_FAILURE);
	}
	buffer = temp;
	temp = NULL;
	buf_size += FIELD_WIDTH + 1;
	sprintf(buffer + offset, "_");
	sprintf(buffer + offset + 1, "%d", m_key->dstPort);
	offset += FIELD_WIDTH + 1;
//	sprintf(buffer + offset, "\0");
}
/

//else{
//	printf("m_key->dstPort == NULL\n");
//}

//sprintf(buffer + offset, "\0");
//printf("m_key string: %s", buffer);
//return buffer;
//m_key_str = buffer;
return buffer;
}
*/

int sampling_check(double sampling_ratio){

	double ratio, random;
	if(sampling_ratio > 1 || sampling_ratio < 0)
		return -1;
	if (sampling_ratio == 0)
		return 0;
	if (sampling_ratio == 1)
			return 1;
	ratio = sampling_ratio*1000000;
	random = rand() % 1000000;
	if(random <= ratio)
		return 1;
	else
		return 0;
}

//int sampling_check(struct monitoringdb *mdb){
//	double sampling_ratio = mdb->sampling_ratio;
//	int k = sub_sampling_check(sampling_ratio);
//	return k;
//}

void set_sampling_ratio(struct monitoringdb *mdb, double ratio){
	mdb->sampling_ratio = ratio;
}

/*void set_n_stats(struct monitoringdb *mdb, int n_stats){
	mdb->n_stats == n_stats;
}
*/

void set_query_time_interval(struct monitoringdb *mdb, double time_interval){
	mdb->query_time_interval = time_interval;
}

void set_overflow_notification_threshold(struct monitoringdb *mdb, uint32_t overflow_threshold){
	mdb->overflow_notification_threshold = overflow_threshold;
}

void printMonitoringTable(struct Hash_Table *t){
	return printHashTable(t);
}
