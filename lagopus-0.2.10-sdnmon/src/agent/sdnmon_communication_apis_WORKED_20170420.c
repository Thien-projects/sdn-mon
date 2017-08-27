/*
 * sdnmon_communication_apis.c
 *
 *  Created on: May 8, 2016
 *      Author: thienphan
 */
#include "lagopus_apis.h"
#include "openflow.h"
#include "lagopus/flowdb.h"
#include "lagopus/meter.h"
#include "lagopus/bridge.h"
#include "lagopus/pbuf.h"

#include "lagopus/monitoringdb.h"
#include "sdnmon_communication_apis.h"
#include "sys/queue.h"

/*
 * @THIEN: 2016-05-09
 * Get m_entry_stats_list of all updated m_entry in monitoringdb
 * (the one that is sent to controller in a previous time and has no current update will not be picked up in this list).
 * This list will be encoded into Experimenter reply message
 * for sending out communication channel to controller
 * Return: m_entry_stats_list
 */
lagopus_result_t
sdnmon_m_entry_stats_get(uint64_t dpid,
		//struct ofp_flow_stats_request *flow_stats_request,
		//struct match_list *match_list,
		struct ofp_experimenter_multipart_header *exper_req,
		struct m_entry_stats_list *m_entry_stats_list, struct ofp_error *error){

	struct bridge *bridge;

	bridge = dp_bridge_lookup_by_dpid(dpid);
	if (bridge == NULL) {
		return LAGOPUS_RESULT_NOT_FOUND;
	}
	return monitoringdb_m_entry_stats(bridge->monitoringdb, exper_req, m_entry_stats_list, error);
}

lagopus_result_t
sdnmon_number_of_entries_get(uint64_t dpid, uint32_t *number_of_flow_entry,
		uint32_t *number_of_m_entry){
	struct bridge *bridge;

	bridge = dp_bridge_lookup_by_dpid(dpid);
	if (bridge == NULL) {
		return LAGOPUS_RESULT_NOT_FOUND;
	}
	*number_of_flow_entry = bridge->monitoringdb->flow_count;
	*number_of_m_entry = bridge->monitoringdb->n_m_entries;
	//*switch_capacity = bridge->monitoringdb->overflow_notification_threshold;
	return LAGOPUS_RESULT_OK;
}

void sdnmon_set_sampling_ratio(uint64_t dpid, double ratio){

	struct bridge *bridge;
	bridge = dp_bridge_lookup_by_dpid(dpid);
	if (bridge == NULL) {
		return LAGOPUS_RESULT_NOT_FOUND;
	}
	printf("set SamplingRatio into: %f\n", ratio);
	return set_sampling_ratio(bridge->monitoringdb, ratio);
}

void sdnmon_set_query_time_interval(uint64_t dpid, uint32_t query_time_interval){

	struct bridge *bridge;
	bridge = dp_bridge_lookup_by_dpid(dpid);
	if (bridge == NULL) {
		return LAGOPUS_RESULT_NOT_FOUND;
	}
	printf("set QueryTimeInterval into: %d\n", query_time_interval);
	return set_query_time_interval(bridge->monitoringdb, query_time_interval);
}

void sdnmon_set_overflow_notification_threshold(uint64_t dpid, uint32_t overflow_threshold){

	struct bridge *bridge;
	bridge = dp_bridge_lookup_by_dpid(dpid);
	if (bridge == NULL) {
		return LAGOPUS_RESULT_NOT_FOUND;
	}
	printf("set OverflowNotificationThreshold into: %d\n", overflow_threshold);
	return set_overflow_notification_threshold(bridge->monitoringdb, overflow_threshold);
}

lagopus_result_t sdnmon_insert_m_entry_from_controller(uint64_t dpid, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, uint8_t proto){

	struct bridge *bridge;
	bridge = dp_bridge_lookup_by_dpid(dpid);
	if (bridge == NULL) {
		return LAGOPUS_RESULT_NOT_FOUND;
	}
	printf("Inserted m_entry into monitoring table\n");
	return insert_m_entry_from_controller(bridge->monitoringdb, src_ip, src_port, dst_ip, dst_port, proto);
}

lagopus_result_t sdnmon_remove_m_entry_from_controller(uint64_t dpid, struct m_key *m_key){

	struct bridge *bridge;
	bridge = dp_bridge_lookup_by_dpid(dpid);
	if (bridge == NULL) {
		return LAGOPUS_RESULT_NOT_FOUND;
	}
	return remove_m_entry_from_controller(bridge->monitoringdb, m_key);
	printf("Removed m_entry from monitoring table\n");
}

lagopus_result_t sdnmon_reset_m_table_from_controller(uint64_t dpid){

	struct bridge *bridge;
	bridge = dp_bridge_lookup_by_dpid(dpid);
	if (bridge == NULL) {
		return LAGOPUS_RESULT_NOT_FOUND;
	}
	printf("Reset monitoring table\n");
	return reset_m_table_from_controller(bridge->monitoringdb);
}
