// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once 

/**
 * Functionality for communicating with Tor.
 */

#include "scheduler.h"

extern const std::string EDC_DEFAULT_TOR_CONTROL;

const bool EDC_DEFAULT_LISTEN_ONION = true;

void edcStartTorControl(boost::thread_group& threadGroup, CScheduler& scheduler);
void edcInterruptTorControl();
void edcStopTorControl();
