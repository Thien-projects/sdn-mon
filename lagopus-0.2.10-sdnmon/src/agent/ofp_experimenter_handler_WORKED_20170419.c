/*
 * Copyright 2014-2016 Nippon Telegraph and Telephone Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include <stdint.h>
#include "lagopus_apis.h"
#include "openflow.h"
#include "openflow13packet.h"
#include "ofp_apis.h"

/*
 * @author: Thien X. Phan
 * 2017-02-27
 */
#include "sdnmon_communication_apis.h"
#include "lagopus/monitoringdb.h"
//

/* send */
/* Send experimenter reply. */
STATIC lagopus_result_t
ofp_experimenter_reply_create(struct channel *channel,
                              struct pbuf **pbuf,
                              struct ofp_header *xid_header,
                              struct ofp_experimenter_header *exper_req) {
  struct ofp_experimenter_header exper_reply;
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (channel != NULL && pbuf != NULL &&
      xid_header != NULL && exper_req != NULL) {
    *pbuf = NULL;
    /* alloc */
    *pbuf = channel_pbuf_list_get(channel,
                                  sizeof(struct ofp_experimenter_header));
    if (*pbuf != NULL) {
      pbuf_plen_set(*pbuf, sizeof(struct ofp_experimenter_header));

      exper_reply.experimenter = exper_req->experimenter;
      exper_reply.exp_type = exper_req->exp_type;

      /* Fill in header. */
      ofp_header_set(&exper_reply.header, channel_version_get(channel),
                     OFPT_EXPERIMENTER, (uint16_t) pbuf_plen_get(*pbuf),
                     xid_header->xid);

      /* Encode message. */
      ret = ofp_experimenter_header_encode(*pbuf, &exper_reply);
      if (ret != LAGOPUS_RESULT_OK) {
        lagopus_msg_warning("FAILED (%s).\n",
                            lagopus_error_get_string(ret));
      }
    } else {
      lagopus_msg_warning("Can't allocate pbuf.\n");
      ret = LAGOPUS_RESULT_NO_MEMORY;
    }

    if (ret != LAGOPUS_RESULT_OK && *pbuf != NULL) {
      channel_pbuf_list_unget(channel, *pbuf);
      *pbuf = NULL;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}

/* RECV */
/* Experimenter packet receive. */
lagopus_result_t
ofp_experimenter_request_handle(struct channel *channel, struct pbuf *pbuf,
                                struct ofp_header *xid_header) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct pbuf *send_pbuf = NULL;
  struct ofp_experimenter_header exper_req;

  /*
   * @author: Thien X. Phan
   * 2017-02-27
   */
  uint8_t data[1];//unsigned char data[4];//
  uint8_t data_overflow_threshold[4];
  uint8_t data_query_time_interval[4];
  uint8_t data_m_entry[13];
  struct ofp_experimenter_data exp_data;
  printf("\n **ofp_experimenter_request_handle(...) called!**\n");
  //

  if (channel != NULL && pbuf != NULL &&
      xid_header != NULL) {
    /* Parse packet. */
    ret = ofp_experimenter_header_decode(pbuf, &exper_req);

    /*
     * @author: Thien X. Phan
     * 2017-02-27
     */
    if (&exper_req != NULL) {
        printf("ofp_experimenter_header:\n");
        printf(" experimenter: %u\n", exper_req.experimenter);
       	printf(" exp_type: %u\n", exper_req.exp_type);
       	//For message: set_sampling_ratio
       	if(exper_req.experimenter == 10 && exper_req.exp_type == 2){
       		printf("Received SET_SAMPLING_RATIO instruction from controller:\n");
       		DECODE_GET(data, 1);
       		printf("sampling_ratio = %u\n", data[0]);
       		double ratio = data[0]/100.0; //test
       		sdnmon_set_sampling_ratio(channel_dpid_get(channel), ratio);
       	}
       	//For message: set_query_time_interval
       	if(exper_req.experimenter == 10 && exper_req.exp_type == 3){
       		uint32_t query_time_interval;
       		printf("Received SET_QUERY_TIME_INTERVAL instruction from controller:\n", data[0]);
       	    DECODE_GET(data_query_time_interval, 4);
       	    query_time_interval = data_query_time_interval[0] | (uint32_t) data_query_time_interval[1] << 8 |
       					(uint32_t) data_query_time_interval[2] << 16 | (uint32_t) data_query_time_interval[3] << 24;
       	    printf("query_time_interval = %d\n", query_time_interval);
       	    sdnmon_set_query_time_interval(channel_dpid_get(channel), query_time_interval);
       	}
       	//For message: set_overflow_notification_threshold
       	if(exper_req.experimenter == 10 && exper_req.exp_type == 4){
       		uint32_t overflow_threshold;
       		printf("Received SET_OVERFLOW_NOTIFICATION_THRESHOLD instruction from controller:\n", data[0]);
       	    DECODE_GET(data_overflow_threshold, 4);
       	    overflow_threshold = data_overflow_threshold[0] | (uint32_t) data_overflow_threshold[1] << 8 |
       					(uint32_t) data_overflow_threshold[2] << 16 | (uint32_t) data_overflow_threshold[3] << 24;
       	    printf("overflow_threshold = %d\n", overflow_threshold);
       	    sdnmon_set_overflow_notification_threshold(channel_dpid_get(channel), overflow_threshold);
       	}
       	//For message: reset_monitoring_table
       	if(exper_req.experimenter == 10 && exper_req.exp_type == 5){
       		printf("Received RESET_MONITORING_TABLE instruction from controller:\n", data[0]);
       		DECODE_GET(data, 1);
       		printf("confirm data = %u\n", data[0]);

       		//sdnmon_reset_m_table_from_controller(channel_dpid_get(channel));
       	}
       	//For message: insert_monitoring_entry
       	if(exper_req.experimenter == 10 && exper_req.exp_type == 6){
       		printf("Received INSERT_MONITORING_ENTRY instruction from controller:\n", data[0]);
       		uint32_t src_ip, dst_ip;
       		uint16_t src_port, dst_port;
       		uint8_t proto;
       		struct m_key *m_key;
       		DECODE_GET(data_m_entry, 13);
       		src_ip = data_m_entry[0] | (uint32_t) data_m_entry[1] << 8 |
       					(uint32_t) data_m_entry[2] << 16 | (uint32_t) data_m_entry[3] << 24;
       		dst_ip = data_m_entry[4] | (uint32_t) data_m_entry[5] << 8 |
       					(uint32_t) data_m_entry[6] << 16 | (uint32_t) data_m_entry[7] << 24;
       		src_port = data_m_entry[8] | (uint16_t) data_m_entry[9] << 8;
       		dst_port = data_m_entry[10] | (uint16_t) data_m_entry[11] << 8;
       		proto = (uint8_t) data_m_entry[12];
       		printf("INSERTED m_entry: ");
       		printf("[srcIP=%d.%d.%d.%d, ",(src_ip & 0xFF), ((src_ip >> 8) & 0xFF),
       					((src_ip >> 16) & 0xFF),((src_ip >> 24) & 0xFF));
       		printf("dstIP=%d.%d.%d.%d, ",(dst_ip & 0xFF), ((dst_ip >> 8) & 0xFF),
       		       					((dst_ip >> 16) & 0xFF),((dst_ip >> 24) & 0xFF));
       		printf("srcPort=%d, dstPort=%d, proto=%d]\n", src_port, dst_port, proto);
       		//Processing to insert that entry into local monitoring table, below:
       		m_key = (struct m_key *)calloc(1, sizeof(struct m_key));
       		m_key->srcIp=src_ip;
       		m_key->dstIp=dst_ip;
       		m_key->srcPort=src_port;
       		m_key->dstPort=dst_port;
       		m_key->proto=proto;
       		sdnmon_insert_m_entry_from_controller(channel_dpid_get(channel), m_key);
       	}
       	//For message: remove_monitoring_entry
       	if(exper_req.experimenter == 10 && exper_req.exp_type == 7){
       		printf("Received REMOVE_MONITORING_ENTRY instruction from controller:\n", data[0]);
       		uint32_t src_ip, dst_ip;
       		uint16_t src_port, dst_port;
       		uint8_t proto;
       		struct m_key *m_key;
       		DECODE_GET(data_m_entry, 13);
       		src_ip = data_m_entry[0] | (uint32_t) data_m_entry[1] << 8 |
       					(uint32_t) data_m_entry[2] << 16 | (uint32_t) data_m_entry[3] << 24;
       		dst_ip = data_m_entry[4] | (uint32_t) data_m_entry[5] << 8 |
       					(uint32_t) data_m_entry[6] << 16 | (uint32_t) data_m_entry[7] << 24;
       		src_port = data_m_entry[8] | (uint16_t) data_m_entry[9] << 8;
       		dst_port = data_m_entry[10] | (uint16_t) data_m_entry[11] << 8;
       		proto = (uint8_t) data_m_entry[12];
       		printf("REMOVED m_entry: ");
       		printf("[srcIP=%d.%d.%d.%d, ",(src_ip & 0xFF), ((src_ip >> 8) & 0xFF),
       					((src_ip >> 16) & 0xFF),((src_ip >> 24) & 0xFF));
       		printf("dstIP=%d.%d.%d.%d, ",(dst_ip & 0xFF), ((dst_ip >> 8) & 0xFF),
       		       					((dst_ip >> 16) & 0xFF),((dst_ip >> 24) & 0xFF));
       		printf("srcPort=%d, dstPort=%d, proto=%d]\n", src_port, dst_port, proto);
       		//Processing to remove that entry from local monitoring table (and marked it into Bloom filter), below:
       		m_key = (struct m_key *)calloc(1, sizeof(struct m_key));
       		m_key->srcIp=src_ip;
       		m_key->dstIp=dst_ip;
       		m_key->srcPort=src_port;
       		m_key->dstPort=dst_port;
       		m_key->proto=proto;
       		sdnmon_remove_m_entry_from_controller(channel_dpid_get(channel), m_key);
       	}
    }
    //

    if (ret == LAGOPUS_RESULT_OK) {
      /* Experimenter request reply. */
      ret = ofp_experimenter_reply_create(channel, &send_pbuf,
                                          xid_header, &exper_req);
      if (ret == LAGOPUS_RESULT_OK) {
        channel_send_packet(channel, send_pbuf);
        ret = LAGOPUS_RESULT_OK;
      } else {
        lagopus_msg_warning("FAILED (%s).\n", lagopus_error_get_string(ret));
      }
    } else {
      lagopus_msg_warning("FAILED (%s).\n", lagopus_error_get_string(ret));
      ret = LAGOPUS_RESULT_OFP_ERROR;
    }

    if (ret != LAGOPUS_RESULT_OK && send_pbuf != NULL) {
      channel_pbuf_list_unget(channel, send_pbuf);
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}
