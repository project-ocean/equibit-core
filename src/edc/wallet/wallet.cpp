// Copyright (c) 2016-2017 The Equibit Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"
#include "wallet/coincontrol.h"
#include "policy/policy.h"
#include "validation.h"
#include "txmempool.h"
#include "base58.h"
#include "random.h"
#include "util.h"

#include <boost/foreach.hpp>

using namespace std;


