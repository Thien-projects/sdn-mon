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

#include "unity.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "lagopus_apis.h"

#include "../dataplane_interface.h"

void
setUp(void) {
}

void
tearDown(void) {
}

void
test_dot1dBaseBridgeAddress(void) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  size_t size;
  uint8_t address[] = {0,0,0,0,0,0};
  uint8_t *value;

  ret = dataplane_bridge_stat_get_address(value, &size);

  TEST_ASSERT_EQUAL_INT64(ret, LAGOPUS_RESULT_OK);
  TEST_ASSERT_EQUAL_UINT32(sizeof(address), size);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(address, value, sizeof(value));
}

