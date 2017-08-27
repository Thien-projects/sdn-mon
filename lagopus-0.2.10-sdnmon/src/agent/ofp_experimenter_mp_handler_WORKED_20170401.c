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

/* SEND */
/* Send experimenter multipart reply. */
STATIC lagopus_result_t
ofp_experimenter_mp_reply_create(
  struct channel *channel,
  struct pbuf_list **pbuf_list,
  struct ofp_header *xid_header,
  struct ofp_experimenter_multipart_header *exper_req) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  uint16_t tmp_length = 0;
  uint16_t length = 0;
  struct ofp_multipart_reply mp_reply;
  struct pbuf *pbuf = NULL;
  struct ofp_experimenter_multipart_header exper_reply;

  if (channel != NULL && pbuf_list != NULL &&
      xid_header != NULL && exper_req != NULL) {

    /* alloc */
    *pbuf_list = pbuf_list_alloc();

    if (*pbuf_list != NULL) {
      pbuf = pbuf_list_last_get(*pbuf_list);

      if (pbuf != NULL) {
        pbuf_plen_set(pbuf, pbuf_size_get(pbuf));

        /* Fill in header. */
        memset(&mp_reply, 0, sizeof(mp_reply));
        ofp_header_set(&mp_reply.header, channel_version_get(channel),
                       OFPT_MULTIPART_REPLY, tmp_length, xid_header->xid);

        mp_reply.type = OFPMP_EXPERIMENTER;
        mp_reply.flags = 0;

        /* Encode multipart reply. */
        ret = ofp_multipart_reply_encode(pbuf, &mp_reply);

        if (ret == LAGOPUS_RESULT_OK) {
          exper_reply.experimenter = exper_req->experimenter;
          exper_reply.exp_type = exper_req->exp_type;

          /* Encode message. */
          ret = ofp_experimenter_multipart_header_encode_list(*pbuf_list,
                &pbuf,
                &exper_reply);

          if (ret == LAGOPUS_RESULT_OK) {
            /* set length for last pbuf. */
            ret = pbuf_length_get(pbuf, &length);
            if (ret == LAGOPUS_RESULT_OK) {
              ret = ofp_header_length_set(pbuf, length);
              if (ret == LAGOPUS_RESULT_OK) {
                pbuf_plen_reset(pbuf);
                ret = LAGOPUS_RESULT_OK;
              } else {
                lagopus_msg_warning("FAILED (%s).\n",
                                    lagopus_error_get_string(ret));
              }
            } else {
              lagopus_msg_warning("FAILED (%s).\n",
                                  lagopus_error_get_string(ret));
            }
          } else {
            lagopus_msg_warning("FAILED (%s).\n",
                                lagopus_error_get_string(ret));
          }
        } else {
          lagopus_msg_warning("FAILED (%s).\n",
                              lagopus_error_get_string(ret));
        }
      } else {
        lagopus_msg_warning("Can't allocate pbuf.\n");
        ret = LAGOPUS_RESULT_NO_MEMORY;
      }
    } else {
      lagopus_msg_warning("Can't allocate pbuf_list.\n");
      ret = LAGOPUS_RESULT_NO_MEMORY;
    }

    if (ret != LAGOPUS_RESULT_OK && *pbuf_list != NULL) {
      pbuf_list_free(*pbuf_list);
      *pbuf_list = NULL;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


/*
 * @author: Thien X. Phan
 * 2017-02-27
 */
static lagopus_result_t
ofp_m_entry_stats_encode(struct pbuf *pbuf, const struct m_key *packet_key, const struct m_statistics *packet_stats)
{
	lagopus_result_t rv = LAGOPUS_RESULT_OK;
	uint16_t *len = NULL; //pointer to pbuf_length
	uint8_t pad = 0;
	uint8_t test_byte = 9;
	/* Size check. */
	//if (pbuf->plen < (sizeof(struct m_statistics) + sizeof(struct m_key))) //dang test send m_statistics (16bytes) + 16 testing bytes //sizeof(struct ofp_flow_stats))  //Error o day -> Found!!!
	if (pbuf->plen < 32) //24) //20) //16) //(sizeof(struct m_statistics) + sizeof(struct m_key)))
		return LAGOPUS_RESULT_OUT_OF_RANGE;

	ENCODE_PUTLL(packet_stats->packet_count); //8
	ENCODE_PUTLL(packet_stats->byte_count);   //8
		ENCODE_PUTC(pad); //put 3 bytes for padding (byte dem)
		ENCODE_PUTC(pad);
		ENCODE_PUTC(pad);
	ENCODE_PUTC(packet_key->proto); //1
	ENCODE_PUTW(packet_key->srcPort); //2
	ENCODE_PUTW(packet_key->dstPort); //2
	ENCODE_PUTL(packet_key->srcIp); //4 (bytes)
	ENCODE_PUTL(packet_key->dstIp); //4

	//printf("ENCODED m_entry_stats: ");
//	printf("[srcIP= %d.%d.%d.%d",(packet_key->srcIp & 0xFF), ((packet_key->srcIp >> 8) & 0xFF),
//			((packet_key->srcIp >> 16) & 0xFF),((packet_key->srcIp >> 24) & 0xFF)); //inet_ntoa(packet_key->srcIp));
//
//	printf(" dstIP= %d.%d.%d.%d",(packet_key->dstIp & 0xFF), ((packet_key->dstIp >> 8) & 0xFF),
//			((packet_key->dstIp >> 16) & 0xFF),((packet_key->dstIp >> 24) & 0xFF)); //inet_ntoa(packet_key->dstIp));
//	printf(" srcPort=%u", packet_key->srcPort);
//	printf(" dstPort=%u", packet_key->dstPort);
//	printf(" proto=%u", packet_key->proto);
//	printf(" packet_count=%u", packet_stats->packet_count);
//	printf(" byte_count=%u]\n", packet_stats->byte_count);

	rv = pbuf_length_get(pbuf, len);
	if(rv == LAGOPUS_RESULT_OK && len != NULL){
		printf("pbuf_length_get(pbuf, len) = %d\n", *len);
	}
	return LAGOPUS_RESULT_OK;
}

/*
 * @THIEN: 2016-05-09
 * Encode a list of m_entry_stats
 */
static lagopus_result_t
ofp_m_entry_stats_encode_list(struct pbuf_list *pbuf_list, struct pbuf **pbuf,
		const struct m_key *packet_key, const struct m_statistics *packet_stats)
{
  struct pbuf *before_pbuf;
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  //printf("   m_entry_stats_encode_list(...) called\n");
  if (pbuf_list == NULL) {
    return ofp_m_entry_stats_encode(*pbuf, packet_key, packet_stats);
  }
  *pbuf = pbuf_list_last_get(pbuf_list);
  if (*pbuf == NULL) {
    return LAGOPUS_RESULT_NO_MEMORY;
  }
  ret = ofp_m_entry_stats_encode(*pbuf, packet_key, packet_stats);
  if (ret == LAGOPUS_RESULT_OUT_OF_RANGE) {
    before_pbuf = *pbuf;
    *pbuf = pbuf_alloc(OFP_PACKET_MAX_SIZE);
    if (*pbuf == NULL) {
      return LAGOPUS_RESULT_NO_MEMORY;
    }

    pbuf_list_add(pbuf_list, *pbuf);
    (*pbuf)->plen = OFP_PACKET_MAX_SIZE;
    //printf("(*pbuf)->plen = %d\n", (*pbuf)->plen);
    ret = ofp_header_mp_copy(*pbuf, before_pbuf);
    if (ret != LAGOPUS_RESULT_OK) {
      return ret;
    }
    ret = ofp_m_entry_stats_encode(*pbuf, packet_key, packet_stats);
  }
  return ret;
}

lagopus_result_t
number_of_entries_encode(struct pbuf *pbuf, const uint32_t number_of_flow_entry, const uint32_t number_of_m_entry)
{
  /* Size check. */
  if (pbuf->plen < 8)
    return LAGOPUS_RESULT_OUT_OF_RANGE;

  /* Encode packet. */
  ENCODE_PUTL(number_of_flow_entry);
  ENCODE_PUTL(number_of_m_entry);
  //ENCODE_PUTL(switch_capacity);
  printf("encoded number_of_flow_entry: %d\n",number_of_flow_entry);
  printf("encoded number_of_m_entry: %d\n",number_of_m_entry);
  //printf("encoded switch_capacity: %d\n",switch_capacity);

  return LAGOPUS_RESULT_OK;
}

static lagopus_result_t
number_of_entries_encode_list(struct pbuf_list *pbuf_list, struct pbuf **pbuf,
		uint32_t number_of_flow_entry, uint32_t number_of_m_entry){
	  struct pbuf *before_pbuf;
	  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

	  if (pbuf_list == NULL) {
	    //return number_of_entries_encode(*pbuf, number_of_flow_entry, number_of_m_entry, switch_capacity);
	    return number_of_entries_encode(*pbuf, number_of_flow_entry, number_of_m_entry);
	  }
	  *pbuf = pbuf_list_last_get(pbuf_list);
	  if (*pbuf == NULL) {
	    return LAGOPUS_RESULT_NO_MEMORY;
	  }
	  //ret = number_of_entries_encode(*pbuf, number_of_flow_entry, number_of_m_entry, switch_capacity);
	  ret = number_of_entries_encode(*pbuf, number_of_flow_entry, number_of_m_entry);
	  if (ret == LAGOPUS_RESULT_OUT_OF_RANGE) {
	    before_pbuf = *pbuf;
	    *pbuf = pbuf_alloc(OFP_PACKET_MAX_SIZE);
	    if (*pbuf == NULL) {
	      return LAGOPUS_RESULT_NO_MEMORY;
	    }
	    pbuf_list_add(pbuf_list, *pbuf);
	    (*pbuf)->plen = OFP_PACKET_MAX_SIZE;
	    ret = ofp_header_mp_copy(*pbuf, before_pbuf);
	    if (ret != LAGOPUS_RESULT_OK) {
	      return ret;
	    }
	    //ret = number_of_entries_encode(*pbuf, number_of_flow_entry, number_of_m_entry, switch_capacity);
	    ret = number_of_entries_encode(*pbuf, number_of_flow_entry, number_of_m_entry);
	  }
	  return ret;
}

/*
 * @THIEN: 2016-05-05
 * Encode a list of m_entry_stats
 * Input: m_entry_stats_list (a list of m_entry_stats)
 * Output: &pbuf_list, containing data of all m_entry stats for sending out communication channel
 */

//Tham khao ham: s_flow_stats_list_encode(*pbuf_list, &pbuf, flow_stats_list) trong ofp_flow_handler.c
static lagopus_result_t
m_entry_stats_list_encode(struct pbuf_list *pbuf_list,
                         struct pbuf **pbuf,
                         struct m_entry_stats_list *m_entry_stats_list) {

	lagopus_result_t res = LAGOPUS_RESULT_ANY_FAILURES;
	//uint16_t match_total_len = 0;
	//uint16_t instruction_total_len = 0;
	uint16_t m_entry_stats_len;
	uint8_t *m_entry_stats_head = NULL;
	struct m_entry_stats *m_entry_stats = NULL;
	int n_m_entry_stats_list=0; //number of m_entry_stats in the list

  if (TAILQ_EMPTY(m_entry_stats_list) == false) {

	 //printf("Encoding m_entries: \n");
    /* encode flow_stats list */
    TAILQ_FOREACH(m_entry_stats, m_entry_stats_list, entry) {

    	n_m_entry_stats_list++;
      /* flow_stats head pointer. */
    	m_entry_stats_head = pbuf_putp_get(*pbuf);

      /* encode flow_stats */
      res = ofp_m_entry_stats_encode_list(pbuf_list, pbuf, &(m_entry_stats->m_key), &(m_entry_stats->stats));  ///////encode a m_entry_stats

      if (res == LAGOPUS_RESULT_OK) {
        /* encode match */
        /*res = ofp_match_list_encode(pbuf_list, pbuf, &(flow_stats->match_list),
                                    &match_total_len);                             //encode match fields
        if (res == LAGOPUS_RESULT_OK) {
        */

            /* Set flow_stats length (match total length +       */
            /*                        instruction total length + */
            /*                        size of ofp_flow_stats).   */
            /* And check overflow.                               */
    	  m_entry_stats_len = 0;// match_total_len;
              res = ofp_tlv_length_sum(&m_entry_stats_len, 32); //24); //20); //16); //8); //testing sending 8 bytes
              	  	  	  	  	  	  //sizeof(struct m_statistics));
              if (res == LAGOPUS_RESULT_OK) {
                            res = ofp_tlv_length_sum(&m_entry_stats_len, 0);//testing
                                                     //sizeof(struct m_key));
              if (res == LAGOPUS_RESULT_OK) {
                res = ofp_multipart_length_set(m_entry_stats_head,
                								m_entry_stats_len);
                if (res != LAGOPUS_RESULT_OK) {
                  lagopus_msg_warning("FAILED (%s).\n",
                                      lagopus_error_get_string(res));
                }
              } else {
                lagopus_msg_warning("over m_entry_stats length.\n");
                break;
              }
              } else {
            	  lagopus_msg_warning("over m_entry_stats length.\n");
              	  break;
              }
/*        } else {
          lagopus_msg_warning("FAILED : ofp_match_list_encode (%s).\n",
                              lagopus_error_get_string(res));
          break;
        }
*/      } else {
        lagopus_msg_warning("FAILED : ofp_m_entry_stats_encode (%s).\n",
                            lagopus_error_get_string(res));
        break;
      }
    }
    	printf("#m_entries sent to switch: %d\n", n_m_entry_stats_list);
  } else {
    /* flow_stats_list is empty. */
    res = LAGOPUS_RESULT_OK;
  }
  //printf("#m_entry_stats: %d\n", n_m_entry_stats_list);
  return res;
}

/*
 * @THIEN: 2016-05-05
 * Create SDN-Mon (Experimenter) multipart reply message
 * Input: m_entry_stats_list (a list of m_entry_stats)
 * Output: &pbuf_list, containing data of all m_entry stats for sending out communication channel
 */
static lagopus_result_t
ofp_sdnmon_mp_reply_create(
  struct channel *channel,
  struct pbuf_list **pbuf_list,
  struct m_entry_stats_list *m_entry_stats_list, //list of m_entry stats for encoding into reply message
  uint32_t number_of_flow_entry,
  uint32_t number_of_m_entry,
  //uint32_t switch_capacity,
  struct ofp_header *xid_header,
  struct ofp_experimenter_multipart_header *exper_req) {

  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  uint16_t tmp_length = 0;
  uint16_t length = 0;
  struct ofp_multipart_reply mp_reply;
  struct pbuf *pbuf = NULL;
  struct ofp_experimenter_multipart_header exper_reply;

  //printf("ofp_sdnmon_mp_reply_create(...) called\n");
  if (channel != NULL && pbuf_list != NULL &&
		  m_entry_stats_list != NULL && xid_header != NULL && exper_req != NULL) {
    /* alloc */
    *pbuf_list = pbuf_list_alloc();

    if (*pbuf_list != NULL) {
      pbuf = pbuf_list_last_get(*pbuf_list);
      if (pbuf != NULL) {
        pbuf_plen_set(pbuf, pbuf_size_get(pbuf));
        /* Fill in header. */
        memset(&mp_reply, 0, sizeof(mp_reply));
        ofp_header_set(&mp_reply.header, channel_version_get(channel),
                       OFPT_MULTIPART_REPLY, tmp_length, xid_header->xid);
        mp_reply.type = OFPMP_EXPERIMENTER;
        mp_reply.flags = 0; //ERROR HERE!! nen set flags = 1, vi luc nay co the chua phai la
        					//multipart message cuoi cung trong chuoi messages cua reply

        /* Encode multipart reply. */
        //ret = ofp_multipart_reply_encode(pbuf, &mp_reply);
        //@THIEN
        //Error chi co the o ham nay? -> co the error ko phai o ham nay
        ret = ofp_multipart_reply_encode_list(*pbuf_list, &pbuf, &mp_reply); //Ham co san cua openflow

		if (ret == LAGOPUS_RESULT_OK) {
			exper_reply.experimenter = exper_req->experimenter;
			exper_reply.exp_type = exper_req->exp_type;

			/* Encode message. */
			ret = ofp_experimenter_multipart_header_encode_list(*pbuf_list,
					&pbuf,
					&exper_reply);

			if (ret == LAGOPUS_RESULT_OK) {
				//Encoding #flow_entries, #m_entries into the reply message
				//ret = number_of_entries_encode_list(*pbuf_list, &pbuf, number_of_flow_entry, number_of_m_entry, switch_capacity);
				ret = number_of_entries_encode_list(*pbuf_list, &pbuf, number_of_flow_entry, number_of_m_entry);

				if (ret == LAGOPUS_RESULT_OK) {
					ret = m_entry_stats_list_encode(*pbuf_list, &pbuf, m_entry_stats_list);  ///encode m_entry_stats_list
				//printf("pbuf size= %d\n", pbuf_size_get(pbuf));
				  //printf("pbuf_list size= %d", (*pbuf_list)->contents_size);
//				  printf("Sent pbuf-data: size=%zu data=", pbuf->size);
//				  	for(size_t i=0; i< (pbuf->size - 65300); i++){
//				  		printf("%02x ", pbuf->data[i]);
//				  	}
//				  	printf("\n");
				  ////////////////////////

					if (ret == LAGOPUS_RESULT_OK) {
						/* set length for last pbuf. */
						ret = pbuf_length_get(pbuf, &length);
						if (ret == LAGOPUS_RESULT_OK) {
							ret = ofp_header_length_set(pbuf, length);
							if (ret == LAGOPUS_RESULT_OK) {
								pbuf_plen_reset(pbuf);
								ret = LAGOPUS_RESULT_OK;
							} else {
								lagopus_msg_warning("FAILED (%s).\n",
										lagopus_error_get_string(ret));
							}
						} else {
							lagopus_msg_warning("FAILED (%s).\n",
									  lagopus_error_get_string(ret));
						}
					} else {
						lagopus_msg_warning("FAILED (%s).\n",
									lagopus_error_get_string(ret));
					}
					//@THIEN
				} else {
					lagopus_msg_warning("FAILED : ofp_multipart_reply_encode (%s).\n",
		                                    lagopus_error_get_string(ret));
				}
		        //
			} else {
				lagopus_msg_warning("FAILED (%s).\n",
											  lagopus_error_get_string(ret));
			}
		} else {
			lagopus_msg_warning("FAILED (%s).\n",
								  lagopus_error_get_string(ret));
		}
      } else {
    	  lagopus_msg_warning("Can't allocate pbuf.\n");
    	  ret = LAGOPUS_RESULT_NO_MEMORY;
      }
    } else {
    	lagopus_msg_warning("Can't allocate pbuf_list.\n");
    	ret = LAGOPUS_RESULT_NO_MEMORY;
    }
    if (ret != LAGOPUS_RESULT_OK && *pbuf_list != NULL) {
    	pbuf_list_free(*pbuf_list);
    	*pbuf_list = NULL;
    }
  } else {
	  //printf("2 [m_entry_stats_list == NULL] \n");
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }
  return ret;
}
//

/* RECV */
/* Experimenter multipart packet receive. */
lagopus_result_t
ofp_experimenter_mp_request_handle(struct channel *channel, struct pbuf *pbuf,
                                   struct ofp_header *xid_header, struct ofp_error *error) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct pbuf_list *pbuf_list = NULL;
  struct ofp_experimenter_multipart_header exper_req;

  /*
   * @author: Thien X. Phan
   * 2017-02-27
   */
  struct m_entry_stats *m_entry_stats = NULL;
  int i = 0;
  uint32_t number_of_flow_entry, number_of_m_entry, switch_capacity;
  //switch_capacity: approximately maximum number of flow entries and m_entries (self-evaluated)
  struct m_entry_stats_list m_entry_stats_list;  //dinh nghia m_entry_stats_list ??
  //

  if (channel != NULL && pbuf != NULL &&
      xid_header != NULL) {
    /* Parse packet. */
    ret = ofp_experimenter_multipart_header_decode(pbuf, &exper_req);
    if (ret == LAGOPUS_RESULT_OK) {

    	//1. get m_entry stats list
    	//2. create reply message containing stats list
    	//3. send out communication channel (to controller)
        TAILQ_INIT(&m_entry_stats_list);
        if ((ret = sdnmon_m_entry_stats_get(channel_dpid_get(channel),  //Viet ham nay => DONE
                                          &exper_req, &m_entry_stats_list, error))
                                 != LAGOPUS_RESULT_OK){
                lagopus_msg_warning("m_entry_stats decode error (%s)\n",
                                    lagopus_error_get_string(ret));
        } else {
        	if((ret = sdnmon_number_of_entries_get(channel_dpid_get(channel), &number_of_flow_entry, &number_of_m_entry))
        			!= LAGOPUS_RESULT_OK){
        		lagopus_msg_warning("number of flows/m_entries decode error (%s)\n",
        		                                    lagopus_error_get_string(ret));
        	} else{

        	//create reply message contained in &pbuf_list
        	ret = ofp_sdnmon_mp_reply_create(channel, &pbuf_list, &m_entry_stats_list,
        										number_of_flow_entry, number_of_m_entry,
												xid_header, &exper_req);

        	/* Experimenter request reply. */
        	//Commented from original code
        	/*ret = ofp_experimenter_mp_reply_create(channel, &pbuf_list,
                                             xid_header, &exper_req);
      	  	  */


      if (ret == LAGOPUS_RESULT_OK) {
        ret = channel_send_packet_list(channel, pbuf_list);
		printf("Sent SDNMON_MULTIPART_REPLY to controller.\n");
		printf(" ");
		time_t t = time(NULL);
		struct tm tm = *localtime(&t);
		printf("Current time: %d-%d-%d %d:%d:%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

        if (ret != LAGOPUS_RESULT_OK) {
          lagopus_msg_warning("Can't write.\n");
          ret = LAGOPUS_RESULT_OFP_ERROR;
        }
      } else {
        lagopus_msg_warning("FAILED (%s).\n", lagopus_error_get_string(ret));
      }
        	}
        }
    } else {
      lagopus_msg_warning("FAILED (%s).\n", lagopus_error_get_string(ret));
      ret = LAGOPUS_RESULT_OFP_ERROR;
    }

    /* free. */
    if (pbuf_list != NULL) {
      pbuf_list_free(pbuf_list);
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}



