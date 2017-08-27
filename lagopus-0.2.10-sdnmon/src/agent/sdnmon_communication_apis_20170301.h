/*
 * sdnmon_communication_apis.h
 *
 *  Created on: May 8, 2016
 *      Author: thienphan
 */

#ifndef SRC_AGENT_SDNMON_COMMUNICATION_APIS_H_
#define SRC_AGENT_SDNMON_COMMUNICATION_APIS_H_

#include "lagopus_apis.h"
#include "openflow.h"
#include "lagopus/flowdb.h"
#include "lagopus/meter.h"
#include "lagopus/bridge.h"
#include "lagopus/pbuf.h"

#include "lagopus/monitoringdb.h"


/**
 * Get array of flow statistics for \b OFPMP_FLOW.
 *
 *     @param[in]	dpid	Datapath id.
 *     @param[in]	flow_stats_reques	A pointer to \e ofp_flow_stats_reques
 *     structure.
 *     @param[in]       match_list      A pointer to list of match.
 *     @param[out]	flow_stats_list	A pointer to list of flow stats.
 *     @param[out]	error	A pointer to \e ofp_error structure.
 *     If errors occur, set filed values.
 *
 *     @retval	LAGOPUS_RESULT_OK	Succeeded.
 *     @retval	LAGOPUS_RESULT_ANY_FAILURES	Failed.
 *
 *     @details	The \e free() of a list element is executed
 *     by the Agent side.
 */
lagopus_result_t
sdnmon_m_entry_stats_get(uint64_t dpid,
		//struct ofp_flow_stats_request *flow_stats_request,
		//struct match_list *match_list,
		struct ofp_experimenter_multipart_header *exper_req,
		struct m_entry_stats_list *m_entry_stats_list, struct ofp_error *error);
/* Multipart - Flow Stats END */

lagopus_result_t
sdnmon_number_of_entries_get(uint64_t dpid, uint32_t *number_of_flow_entry,
		uint32_t *number_of_m_entry);

void sdnmon_set_sampling_ratio(uint64_t dpid, double ratio);

/*
 * @THIEN: 2016-05-09
 * Encode a list of m_entry_stats
 * Input: m_entry_stats_list (a list of m_entry_stats)
 * Output: &pbuf_list, containing data of all m_entry stats for sending out communication channel
 */

/*lagopus_result_t
m_entry_stats_list_encode(struct pbuf_list *pbuf_list,
                         struct pbuf **pbuf,
                         struct m_entry_stats_list *m_entry_stats_list);
*/

#endif /* SRC_AGENT_SDNMON_COMMUNICATION_APIS_H_ */
