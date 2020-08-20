/*
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include <nlohmann/json.hpp>

#include "CB_EVENT.h"

void to_json(nlohmann::json &j, const CB_EVENT &event);
void to_json(nlohmann::json &j, const CB_EVENT_PROCESS_INFO &info);
void to_json(nlohmann::json &j, const CB_EVENT_PROCESS_START &data);
void to_json(nlohmann::json &j, const CB_EVENT_PROCESS_EXIT &data);
void to_json(nlohmann::json &j, const CB_EVENT_MODULE_LOAD &data);
void to_json(nlohmann::json &j, const CB_EVENT_FILE_GENERIC &data);
void to_json(nlohmann::json &j, const CB_SOCK_ADDR &data);
void to_json(nlohmann::json &j, const CB_EVENT_NETWORK_CONNECT &data);
void to_json(nlohmann::json &j, const CB_EVENT_DNS_RESPONSE &data);
void to_json(nlohmann::json &j, const CB_EVENT_BLOCK &data);
