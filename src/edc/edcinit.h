// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once


#include <string>
#include "scheduler.h"


bool EdcAppInit(boost::thread_group& threadGroup, CScheduler& scheduler, const char * );
void edcInterrupt(boost::thread_group& threadGroup);
