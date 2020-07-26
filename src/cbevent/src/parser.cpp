/*
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

#include "CB_EVENT_JSON.h"

using json = nlohmann::json;

static void convert_cbevent_input_to_json(std::istream &in)
{
	CB_EVENT event = {};
	for (unsigned int i = 0;
	     in.read(reinterpret_cast<char *>(&event), sizeof(event)); ++i) {
		json j = event;
		// Dump the output in JSON format
		std::cout << j.dump(2) << std::endl;
	}

}

int main(int argc, char *argv[])
{
	if (argc > 1) {
		std::ifstream input(argv[1], std::ios::in | std::ios::binary);
		convert_cbevent_input_to_json(input);
		input.close();
	} else {
		convert_cbevent_input_to_json(std::cin);
	}

	return 0;
}
