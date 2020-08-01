/*
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <arpa/inet.h>

#include "CB_EVENT_JSON.h"

using json = nlohmann::json;

NLOHMANN_JSON_SERIALIZE_ENUM(
	CB_EVENT_TYPE,
	{ { CB_EVENT_TYPE_UNKNOWN, "Unknown" },
	  { CB_EVENT_TYPE_PROCESS_START, "Process start" },
	  { CB_EVENT_TYPE_PROCESS_EXIT, "Process exit" },
	  { CB_EVENT_TYPE_MODULE_LOAD, "Module load" },
	  { CB_EVENT_TYPE_FILE_CREATE, "File create" },
	  { CB_EVENT_TYPE_FILE_DELETE, "File delete" },
	  { CB_EVENT_TYPE_FILE_WRITE, "File write" },
	  { CB_EVENT_TYPE_FILE_CLOSE, "File close" },
	  { CB_EVENT_TYPE_NET_CONNECT_PRE, "Network connection pre-connect" },
	  { CB_EVENT_TYPE_NET_CONNECT_POST, "Network connection post-connect" },
	  { CB_EVENT_TYPE_NET_ACCEPT, "Network connection accept" },
	  { CB_EVENT_TYPE_DNS_RESPONSE, "DNS response" },
	  { CB_EVENT_TYPE_PROC_ANALYZE, "Process analyze" },
	  { CB_EVENT_TYPE_PROCESS_BLOCKED, "Process blocked" },
	  { CB_EVENT_TYPE_PROCESS_NOT_BLOCKED, "Process not blocked" },
	  { CB_EVENT_TYPE_WEB_PROXY, "Web proxy" },
	  { CB_EVENT_TYPE_HEARTBEAT, "Heartbeat" } })

void to_json(json &j, const CB_EVENT &event)
{
	j["type"]	  = event.eventType;
	j["process info"] = event.procInfo;

	switch (event.eventType) {
	case CB_EVENT_TYPE_PROCESS_START:
		j["Details"] = event.processStart;
		break;
	case CB_EVENT_TYPE_PROCESS_EXIT:
		j["Details"] = event.processExit;
		break;
	case CB_EVENT_TYPE_MODULE_LOAD:
		j["Details"] = event.moduleLoad;
		break;
	case CB_EVENT_TYPE_FILE_CREATE:
	case CB_EVENT_TYPE_FILE_DELETE:
	case CB_EVENT_TYPE_FILE_WRITE:
	case CB_EVENT_TYPE_FILE_CLOSE:
		j["Details"] = event.fileGeneric;
		break;
	case CB_EVENT_TYPE_NET_CONNECT_PRE:
	case CB_EVENT_TYPE_NET_CONNECT_POST:
	case CB_EVENT_TYPE_NET_ACCEPT:
	case CB_EVENT_TYPE_WEB_PROXY:
		j["Details"] = event.netConnect;
		break;
	case CB_EVENT_TYPE_DNS_RESPONSE:
		j["Details"] = event.dnsResponse;
		break;
	case CB_EVENT_TYPE_PROCESS_BLOCKED:
	case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
		j["Details"] = event.blockResponse;
		break;
	case CB_EVENT_TYPE_PROC_ANALYZE:
	case CB_EVENT_TYPE_HEARTBEAT:
	default:
		break;
	}
}

void to_json(json &j, const CB_EVENT_PROCESS_INFO &info)
{
	j["PID"]		= info.pid;
	j["Windows start time"] = info.process_start_time;
	j["Windows event time"] = info.event_time;
}

void to_json(json &j, const CB_EVENT_PROCESS_START &data)
{
	j["Parent PID"] = data.parent;
	j["UID"]	= data.uid;
	j["Start type"] = data.start_action; // 1 = FORK 2 = EXEC
	j["Observed"]	= data.observed; // Flag to identify if the start was
	// actually observed, or this fake
	j["INode"]	  = data.inode; // If we have it otherwise 0
	j["Path"]	  = data.path;
	j["Command line"] = data.cmdLine.v;
	j["Path found"]	  = data.path_found;
}

void to_json(json &j, const CB_EVENT_PROCESS_EXIT &data)
{
	j["PID"] = data.pid;
}

void to_json(json &j, const CB_EVENT_MODULE_LOAD &data)
{
	j["Module name"]  = data.moduleName;
	j["Base address"] = data.baseaddress;
}

NLOHMANN_JSON_SERIALIZE_ENUM(CB_FILE_TYPE,
			     { { filetypeUnknown, "Unknown" },
			       { filetypePe, "PE" },
			       { filetypeElf, "ELF" },
			       { filetypeUniversalBin, "Universal Bin" },
			       { filetypeEicar, "EICAR" },
			       { filetypeOfficeLegacy, "Office Legacy" },
			       { filetypeOfficeOpenXml, "Office OpenXML" },
			       { filetypePdf, "PDF" },
			       { filetypeArchivePkzip, "PKZIP" },
			       { filetypeArchiveLzh, "LZH" },
			       { filetypeArchiveLzw, "LZW" },
			       { filetypeArchiveRar, "RAR" },
			       { filetypeArchiveTar, "TAR" },
			       { filetypeArchive7zip, "7ZIP" } });

void to_json(json &j, const CB_EVENT_FILE_GENERIC &data)
{
	j["File path"] = data.path;
	j["File type"] = data.file_type;
}

void to_json(json &j, const CB_SOCK_ADDR &data)
{
	char localSocketString[INET6_ADDRSTRLEN];
	j["Address"] = inet_ntop(data.ss_addr.ss_family, &data.as_in4.sin_addr,
				 localSocketString, INET6_ADDRSTRLEN);
	j["Port"]    = data.as_in4.sin_port;
}

void to_json(json &j, const CB_EVENT_NETWORK_CONNECT &data)
{
	j["Protocol"]	    = data.protocol;
	j["Local address"]  = data.localAddr;
	j["Remote address"] = data.remoteAddr;
	//	j["Server"]	    = data.actual_server;
	j["Port"] = data.actual_port;
}

void to_json(json &j, const CB_EVENT_DNS_RESPONSE &data)
{
	// TODO
}

NLOHMANN_JSON_SERIALIZE_ENUM(ProcessBlockType,
			     { { BlockDuringProcessStartup, "At startup" },
			       { ProcessTerminatedAfterStartup,
				 "After startup" } });

NLOHMANN_JSON_SERIALIZE_ENUM(TerminateFailureReason,
			     { { TerminateFailureReasonNone, "Success" },
			       { ProcessOpenFailure, "Process open failure" },
			       { ProcessTerminateFailure, "Failed" } });

void to_json(json &j, const CB_EVENT_BLOCK &data)
{
	j["Process blocked"]		= data.blockType;
	j["Process termination result"] = data.failureReason;
	j["Result code"]		= data.failureReasonDetails;
	j["UID"]			= data.uid;
	j["INode"]	  = data.inode; // If we have it otherwise 0
	j["Path"]	  = data.path;
	j["Command line"] = data.cmdLine.v;
	j["Path found"]	  = data.path_found;
}
