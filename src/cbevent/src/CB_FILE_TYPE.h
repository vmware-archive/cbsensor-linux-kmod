/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

enum CB_FILE_TYPE {
	// TODO: This enum list is taken from the protobuf.
	// It would be better to get it from that header instead.
	filetypeUnknown = 0x0000,
	filetypePe = 0x0001, // windows
	filetypeElf = 0x0002, // linux
	filetypeUniversalBin = 0x0003, // osx
	filetypeEicar = 0x0008,
	filetypeOfficeLegacy = 0x0010,
	filetypeOfficeOpenXml = 0x0011,
	filetypePdf = 0x0030,
	filetypeArchivePkzip = 0x0040,
	filetypeArchiveLzh = 0x0041,
	filetypeArchiveLzw = 0x0042,
	filetypeArchiveRar = 0x0043,
	filetypeArchiveTar = 0x0044,
	filetypeArchive7zip = 0x0045
};
