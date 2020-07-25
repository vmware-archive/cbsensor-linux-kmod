/*
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

#include "CB_EVENT_JSON.h"

using json = nlohmann::json;

int main(int argc, char *argv[])
{
	json j;

	std::ifstream input(argv[1], std::ios::in | std::ios::binary);
	CB_EVENT      event = {};
	for (unsigned int i = 0;
	     input.read(reinterpret_cast<char *>(&event), sizeof(event)); ++i) {
		j[i] = event;
	}
	input.close();

	// Dump the output in JSON format
	std::cout << j.dump(2) << std::endl;

	return 0;
}
