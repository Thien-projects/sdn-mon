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

/**
 *      @file   flowinfo_mpls.c
 *      @brief  Optimized flow database for dataplane, for MPLS
 */

#include <stdlib.h>
#include <sys/queue.h>

#include "openflow.h"
#include "lagopus/ethertype.h"
#include "lagopus/flowdb.h"
#include "pktbuf.h"
#include "packet.h"

#include "lagopus/flowinfo.h"

#define OXM_FIELD_TYPE(field) ((field) >> 1)
#define MPLS_LABEL_BITLEN     20

static lagopus_result_t
add_flow_mpls(struct flowinfo *, struct flow *);
static lagopus_result_t
del_flow_mpls(struct flowinfo *, struct flow *);
static struct flow *
match_flow_mpls(struct flowinfo *, struct lagopus_packet *, int32_t *);
static struct flow *
find_flow_mpls(struct flowinfo *, struct flow *);
static void
destroy_flowinfo_mpls(struct flowinfo *);

static struct match *
get_match_mpls_label(struct match_list *match_list, uint32_t *label) {
  struct match *match;

  TAILQ_FOREACH(match, match_list, entry) {
    if (OXM_FIELD_TYPE(match->oxm_field) == OFPXMT_OFB_MPLS_LABEL) {
      OS_MEMCPY(label, match->oxm_value, sizeof(*label));
      break;
    }
  }
  return match;
}

static void
freeup_flowinfo(void *val) {
  struct flowinfo *flowinfo;

  flowinfo = val;
  flowinfo->destroy_func(flowinfo);
}

struct flowinfo *
new_flowinfo_mpls(void) {
  struct flowinfo *self;

  self = calloc(1, sizeof(struct flowinfo));
  if (self != NULL) {
    lagopus_hashmap_create(&self->hashmap, LAGOPUS_HASHMAP_TYPE_ONE_WORD,
                           freeup_flowinfo);
    self->misc = new_flowinfo_basic();
    self->add_func = add_flow_mpls;
    self->del_func = del_flow_mpls;
    self->match_func = match_flow_mpls;
    self->find_func = find_flow_mpls;
    self->destroy_func = destroy_flowinfo_mpls;
  }
  return self;
}

static void
destroy_flowinfo_mpls(struct flowinfo *self) {
  lagopus_hashmap_destroy(&self->hashmap, true);
  self->misc->destroy_func(self->misc);
  free(self);
}

static lagopus_result_t
add_flow_mpls(struct flowinfo *self, struct flow *flow) {
  struct match *match;
  struct flowinfo *flowinfo;
  uint32_t label;
  uint32_t mpls_lse;
  lagopus_result_t rv;

  match = get_match_mpls_label(&flow->match_list, &label);
  if (match != NULL) {
    SET_MPLS_LSE(mpls_lse, OS_NTOHL(label), 0, 0, 0);
    rv = lagopus_hashmap_find_no_lock(&self->hashmap,
                                      (void *)mpls_lse, (void *)&flowinfo);
    if (rv != LAGOPUS_RESULT_OK) {
      void *val;

      flowinfo = new_flowinfo_basic();
      val = flowinfo;
      rv = lagopus_hashmap_add_no_lock(&self->hashmap, (void *)mpls_lse,
                                       (void *)&val, false);
      if (rv != LAGOPUS_RESULT_OK) {
        goto out;
      }
    }
    rv = flowinfo->add_func(flowinfo, flow);
    match->except_flag = true;
  } else {
    rv = self->misc->add_func(self->misc, flow);
  }
  if (rv == LAGOPUS_RESULT_OK) {
    self->nflow++;
  }
out:
  return rv;
}

static lagopus_result_t
del_flow_mpls(struct flowinfo *self, struct flow *flow) {
  struct flowinfo *flowinfo;
  uint32_t label;
  uint32_t mpls_lse;
  lagopus_result_t rv;

  if (get_match_mpls_label(&flow->match_list, &label) != NULL) {
    SET_MPLS_LSE(mpls_lse, OS_NTOHL(label), 0, 0, 0);
    rv = lagopus_hashmap_find_no_lock(&self->hashmap,
                                      (void *)mpls_lse, (void *)&flowinfo);
    if (rv == LAGOPUS_RESULT_OK) {
      rv = flowinfo->del_func(flowinfo, flow);
    }
  } else {
    rv = self->misc->del_func(self->misc, flow);
  }
  if (rv == LAGOPUS_RESULT_OK) {
    self->nflow--;
  }
  return rv;
}

static struct flow *
match_flow_mpls(struct flowinfo *self, struct lagopus_packet *pkt,
                int32_t *pri) {
  struct flowinfo *flowinfo;
  struct flow *flow, *alt_flow;
  uint32_t mpls_lse;
  lagopus_result_t rv;

  flow = NULL;
  SET_MPLS_LSE(mpls_lse, MPLS_LBL(pkt->mpls->mpls_lse), 0, 0, 0);
  rv = lagopus_hashmap_find_no_lock(&self->hashmap, (void *)mpls_lse,
                                    (void *)&flowinfo);
  if (rv == LAGOPUS_RESULT_OK) {
    flow = flowinfo->match_func(flowinfo, pkt, pri);
  }
  alt_flow = self->misc->match_func(self->misc, pkt, pri);
  if (alt_flow != NULL) {
    flow = alt_flow;
  }
  return flow;
}

static struct flow *
find_flow_mpls(struct flowinfo *self, struct flow *flow) {
  struct flowinfo *flowinfo;
  uint32_t label;
  uint32_t mpls_lse;

  if (get_match_mpls_label(&flow->match_list, &label) != NULL) {
    SET_MPLS_LSE(mpls_lse, OS_NTOHL(label), 0, 0, 0);
    if (lagopus_hashmap_find_no_lock(&self->hashmap, (void *)mpls_lse,
                                     (void *)&flowinfo) != LAGOPUS_RESULT_OK) {
      return NULL;
    }
    return flowinfo->find_func(flowinfo, flow);
  } else {
    return self->misc->find_func(self->misc, flow);
  }
}
