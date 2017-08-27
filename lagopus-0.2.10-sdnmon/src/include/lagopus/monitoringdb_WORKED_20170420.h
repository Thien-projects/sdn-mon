/*
 * monitoringdb.h
 *
 *  Created on: Aug 6, 2015
 *      Author: thien
 */

#ifndef SRC_INCLUDE_LAGOPUS_MONITORINGDB_H_
#define SRC_INCLUDE_LAGOPUS_MONITORINGDB_H_

/*
#ifdef HAVE_DPDK
#include "rte_config.h"
#include "rte_rwlock.h"
#endif /* HAVE_DPDK */

#include "lagopus/pbuf.h"
#include "queue.h"

#include "openflow13.h"
#include "lagopus_apis.h"
#include "openflow.h"
#include "ofcache.h"
#include "lagopus/monitoring_hash_table.h"
//#include "../agent/sdnmon_communication_apis.h"
//#include "pktbuf.h"

/*
 * monitoringdb lock primitive.
 */
/*
#ifdef HAVE_DPDK
rte_rwlock_t monitoringdb_update_lock;
rte_rwlock_t dpmgr_lock;

#define MONITORINGDB_RWLOCK_INIT()
#define MONITORINGDB_RWLOCK_RDLOCK()  do {                                    \
    rte_rwlock_read_lock(&dpmgr_lock);                                  \
  } while(0)
#define MONITORINGDB_RWLOCK_WRLOCK()  do {                                    \
    rte_rwlock_write_lock(&dpmgr_lock);                                 \
  } while(0)
#define MONITORINGDB_RWLOCK_RDUNLOCK() do {                                   \
    rte_rwlock_read_unlock(&dpmgr_lock);                                \
  } while(0)
#define MONITORINGDB_RWLOCK_WRUNLOCK() do {                                   \
    rte_rwlock_write_unlock(&dpmgr_lock);                               \
  } while(0)
#define MONITORINGDB_UPDATE_CHECK() do {                      \
    rte_rwlock_read_lock(&monitoringdb_update_lock);          \
    rte_rwlock_read_unlock(&monitoringdb_update_lock);        \
  } while (0)
#define MONITORINGDB_UPDATE_BEGIN() do {               \
    rte_rwlock_write_lock(&monitoringdb_update_lock);  \
  } while (0)
#define MONITORINGDB_UPDATE_END() do {                        \
    rte_rwlock_write_unlock(&monitoringdb_update_lock);       \
  } while (0)
#else
pthread_rwlock_t monitoringdb_update_lock;
pthread_rwlock_t dpmgr_lock;
#define MONITORINGDB_RWLOCK_INIT() do {                                       \
    pthread_rwlock_init(&monitoringdb_update_lock, NULL);                     \
    pthread_rwlock_init(&dpmgr_lock, NULL);                             \
  } while(0)
#define MONITORINGDB_RWLOCK_RDLOCK()  do {                                    \
    pthread_rwlock_rdlock(&dpmgr_lock);                                 \
  } while(0)
#define MONITORINGDB_RWLOCK_WRLOCK()  do {                                    \
    pthread_rwlock_wrlock(&dpmgr_lock);                                 \
  } while(0)
#define MONITORINGDB_RWLOCK_RDUNLOCK() do {                                   \
    pthread_rwlock_unlock(&dpmgr_lock);                                 \
  } while(0)
#define MONITORINGDB_RWLOCK_WRUNLOCK() do {                                   \
    pthread_rwlock_unlock(&dpmgr_lock);                                 \
  } while(0)
#define MONITORINGDB_UPDATE_CHECK() do {                      \
    pthread_rwlock_rdlock(&monitoringdb_update_lock);    \
    pthread_rwlock_unlock(&monitoringdb_update_lock);     \
  } while (0)
#define MONITORINGDB_UPDATE_BEGIN() do {                      \
    pthread_rwlock_wrlock(&monitoringdb_update_lock);    \
  } while (0)
#define MONITORINGDB_UPDATE_END() do {                        \
    pthread_rwlock_unlock(&monitoringdb_update_lock);     \
  } while (0)
#endif /* HAVE_DPDK */


#define MAX_M_ENTRIES 1000

/* Monitoring key (5-tuple). */
struct m_key {
	uint32_t  srcIp; //struct  in_addr srcIp;
	uint16_t srcPort; //uint8_t srcPort;
	uint32_t  dstIp; //struct in_addr dstIp; //
	uint16_t  dstPort; //uint8_t  dstPort;
	uint8_t proto;
};

/*struct m_key {
	unsigned char  srcIp[4];
	uint16_t srcPort;
	unsigned char  dstIp[4];
	uint16_t  dstPort;
	uint8_t proto;
};*/

struct m_statistics {
	  /* Statistics. */
	  uint64_t packet_count;
	  uint64_t byte_count;
};

/* Multipart - M_Entry Stats */
/**
 * M_entry stats.
 */
struct m_entry_stats{
	TAILQ_ENTRY(m_entry_stats) entry;
	struct m_statistics stats;
	struct m_key m_key;
	//struct match_list match_list;
};

/**
 * m_entry stats list.
 */
TAILQ_HEAD(m_entry_stats_list, m_entry_stats);

/* Monitoring entry. */
struct m_entry {

  struct m_key *m_key;
  struct m_statistics **stats_list;
  int n_stats; /*number of statistics items in this m_entry, correspond to number of statistics fields in m_table,
  	  	  	  	 this value can be adjusted by controller*/

  /* M-Table ID. */
  uint8_t m_table_id;

  /* Creation time. */
  struct timespec create_time;

  /* Last updated time. */
  struct timespec update_time;

};

/* Monitoring table. */
/*struct m_table {
  /* List of m_entry. /
  //struct m_entry_list m_entries[MAX_M_ENTRIES];

	int nm_entry;
	struct m_entry **m_entries;

  /* count the number of entries. /
  uint64_t count;  /*number of existing entries in the table./
  uint64_t lookup_count;
  uint64_t matched_count;

  //uint8_t m_table_id;

};*/

#define MONITORINGDB_TABLE_SIZE_MAX 10000  //255


/* Monitoring extension database. */
struct monitoringdb {
  /* Read-write lock. */
//#ifdef HAVE_DPDK
//  rte_rwlock_t rwlock;
//#else
//  pthread_rwlock_t rwlock;
//#endif /* HAVE_DPDK */

  /* Monitoring table size. */
  //uint8_t m_table_size;

  /* Monitoring table. */
  //struct m_table **m_tables;

  //struct m_table *m_table;
  struct Hash_Table *hash_table;

  double sampling_ratio;
  double query_time_interval; //time interval between each 2 continuous queries from controller
  uint32_t overflow_notification_threshold;
  int n_stats; //number of statistics items in m_table;

  /*
   * @author: Thien X. Phan
   * 2017-02-27
   */
  int n_m_entries; //current number of m_entries in m_table
  int flow_count;  //current number of flow entries in flow tables
  //

  //for debugging
  int n_flows, n_bloom_members;
};

/**
 * Allocate a new monitoring database.
 *
 *
 * @retval NULL Allocation failed.
 * @retval Non-NULL Allocation success.
 */
struct monitoringdb *monitoringdb_alloc();

/**
 * Free flow database.
 *
 * @param[in]   monitoringdb  Monitoring database to be freed.
 */
void
monitoringdb_free(struct monitoringdb *monitoringdb);

/**
 * Add monitoring entry to the monitoring database.
 *
 * @param[in]   m_table  m_table structure of the monitoring table.
 * @param[in]   m_entry   m_entry structure of the monitoring entry.
 *
 * @retval LAGOPUS_RESULT_OK            Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS  Failed, invalid argument(s).
 * @retval LAGOPUS_RESULT_NO_MEMORY     Failed, no memory.
 * @retval LAGOPUS_RESULT_OFP_ERROR     Failed with OFP error message.
 */
/*lagopus_result_t
monitoringdb_m_entry_add(struct m_table *m_table, struct m_entry *m_entry);
*/

//struct m_key *extract_m_key_from_packet(struct lagopus_packet *pkt);
lagopus_result_t extract_5tuple_from_packet(struct lagopus_packet *pkt, uint32_t *srcIp, uint16_t *srcPort, uint32_t *dstIp, uint16_t *dstPort, uint8_t *proto);

//New: directly create hash_value of m-entry from its 5-tuple integer values
//unsigned int hash_m_key(struct m_key *m_key);
unsigned int hash_5tuple(uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort, uint8_t proto);

/*lagopus_result_t
monitoringdb_m_entry_add(struct monitoringdb *mdb, struct lagopus_packet *pkt, struct m_key *key, char *m_key_str);
*/

/*
 * @Xuan Thien Phan
 * 2017-04-13
 * New version of function monitoringdb_m_entry_add(...)
 */
//lagopus_result_t
//monitoringdb_m_entry_add(struct monitoringdb *mdb, uint64_t byte_count_of_arriving_entry, struct m_key *key, unsigned int entry_hash_value);
lagopus_result_t
monitoringdb_m_entry_add(struct monitoringdb *mdb, uint64_t byte_count_of_arriving_entry, uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort, uint8_t proto, unsigned int entry_hash_value);

lagopus_result_t
insert_m_entry_from_controller(struct monitoringdb *mdb, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, uint8_t proto);
//lagopus_result_t
//insert_m_entry_from_controller(struct monitoringdb *mdb, struct m_key *key);
//lagopus_result_t
//insert_m_entry_from_controller(struct monitoringdb *mdb, uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort, uint8_t proto);

lagopus_result_t
remove_m_entry_from_controller(struct monitoringdb *mdb, struct m_key *key);
//lagopus_result_t
//remove_m_entry_from_controller(struct monitoringdb *mdb, uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort, uint8_t proto);

lagopus_result_t
reset_m_table_from_controller(struct monitoringdb *mdb);
/**
 * Delete monitoring entry from the monitoring database.
 *
 * @param[in]   m_table  m_table structure of the monitoring table.
 * @param[in]   m_entry   m_entry structure of the monitoring entry.
 *
 * @retval LAGOPUS_RESULT_OK            Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS  Failed, invalid argument(s).
 * @retval LAGOPUS_RESULT_NO_MEMORY     Failed, no memory.
 * @retval LAGOPUS_RESULT_OFP_ERROR     Failed with OFP error message.
 */

//lagopus_result_t
//monitoringdb_m_entry_delete(struct monitoringdb *mdb, struct m_entry *m_entry);

/**
 * Lookup a monitoring entry in the monitoring database based on entry's key.
 *
 * @param[in]   m_table   m_table structure of the monitoring table.
 * @param[in]   m_key   m_key structure to lookup.
 * @param[out]   m_entry   returned m_entry if found.
 *
 * @retval LAGOPUS_RESULT_OK            Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS  Failed, invalid argument(s).
 * @retval LAGOPUS_RESULT_NO_MEMORY     Failed, no memory.
 * @retval LAGOPUS_RESULT_OFP_ERROR     Failed with OFP error message.
 */

/*lagopus_result_t
monitoringdb_m_entry_lookup(struct monitoringdb *mdb, struct m_key *m_key, struct m_entry *m_entry);
*/

//struct Hash_Entry *monitoringdb_lookup_and_update_m_entry(struct monitoringdb *mdb, char *m_key_str, struct lagopus_packet *pkt);
struct Hash_Entry *monitoringdb_lookup_and_update_m_entry(struct monitoringdb *mdb, unsigned int entry_hash_value, uint64_t byte_count_of_arriving_packet);

//unused function
//struct m_entry *monitoringdb_lookup_m_entry_by_key(struct monitoringdb *mdb, struct m_key *m_key);

//unused function
//struct m_entry *monitoringdb_lookup_m_entry_by_packet(struct monitoringdb *mdb, struct lagopus_packet *pkt);

//lagopus_result_t
//monitoringdb_m_entry_update_stats(struct monitoringdb *mdb, struct m_key *m_key, struct lagopus_packet *pkt);

/*
 * @THIEN - 2016-05-09
 * Traverse monitoring table to collect a list of stats of all m_entries
 * Return: m_entry_stats_list (a queue of m_entry_stats)
 */
lagopus_result_t monitoringdb_m_entry_stats(struct monitoringdb *mdb,
		struct ofp_experimenter_multipart_header *exper_req,
		struct m_entry_stats_list *m_entry_stats_list,
		struct ofp_error *error);

char *m_key_to_string(struct m_key *m_key); //, char *m_key_str);

//int sampling_check(struct monitoringdb *mdb);
int sampling_check(double sampling_ratio);

void set_sampling_ratio(struct monitoringdb *mdb, double ratio);

//void set_n_stats(struct monitoringdb *mdb, int n_stats);

void set_query_time_interval(struct monitoringdb *mdb, double time_interval);
void set_overflow_notification_threshold(struct monitoringdb *mdb, uint32_t overflow_threshold);
/**
 * Initialize lock of the monitoring database.
 *
 * @param[in]   monitoringdb  Monitoring database to be locked.
 */
void printMonitoringTable(struct Hash_Table *t);

/*
static inline void
monitoringdb_lock_init(struct monitoringdb *monitoringdb) {
  (void) monitoringdb;
  MONITORINGDB_RWLOCK_INIT();
}*/

/**
 * Read lock the monitoring database.
 *
 * @param[in]   monitoringdb  Monitoring database to be locked.
 */
/*
static inline void
monitoringdb_rdlock(struct monitoringdb *monitoringdb) {
  (void) monitoringdb;
  MONITORINGDB_RWLOCK_RDLOCK();
}*/

/**
 * Check write lock the flow database.
 *
 * @param[in]   flowdb  Flow database to be locked.
 */
/*
static inline void
monitoringdb_check_update(struct monitoringdb *monitoringdb) {
  (void) monitoringdb;
  MONITORINGDB_UPDATE_CHECK();
}*/

/**
 * Write lock the flow database.
 *
 * @param[in]   flowdb  Flow database to be locked.
 */
/*
static inline void
monitoringdb_wrlock(struct monitoringdb *monitoringdb) {
  (void) monitoringdb;
  MONITORINGDB_UPDATE_BEGIN();
  MONITORINGDB_RWLOCK_WRLOCK();
}*/

/**
 * Unlock read lock the flow database.
 *
 * @param[in]   flowdb  Flow database to be unlocked.
 */
/*
static inline void
monitoringdb_rdunlock(struct monitoringdb *monitoringdb) {
  (void) monitoringdb;
  MONITORINGDB_RWLOCK_RDUNLOCK();
}
*/
/**
 * Unlock write lock the flow database.
 *
 * @param[in]   flowdb  Flow database to be unlocked.
 */
/*
static inline void
monitoringdb_wrunlock(struct monitoringdb *monitoringdb) {
  (void) monitoringdb;
  MONITORINGDB_RWLOCK_WRUNLOCK();
  MONITORINGDB_UPDATE_END();
}
*/
/*static inline struct m_table *
m_table_lookup(struct monitoringdb *mdb, uint8_t m_table_id) {
  return monitoringdb->m_tables[table_id];
}
*/

struct timespec now_ts;

/*static inline struct timespec
get_current_time(void) {
  struct timespec ts;

  // XXX lock /
  clock_gettime(CLOCK_MONOTONIC, &now_ts);
  ts = now_ts;

  return ts;
}
*/

/**
 * initialize flow timer related structure.
 */
void init_flow_timer(void);

#endif /* SRC_INCLUDE_LAGOPUS_MONITORINGDB_H_ */
