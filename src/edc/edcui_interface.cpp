// Copyright (c) 2010-2016 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcui_interface.h"
#include "edcutil.h"

CEDCClientUIInterface edcUiInterface;

bool edcInitError(const std::string& str)
{
    edcUiInterface.ThreadSafeMessageBox(str, "", CEDCClientUIInterface::MSG_ERROR);
    return false;
}

void edcInitWarning(const std::string& str)
{
    edcUiInterface.ThreadSafeMessageBox(str, "", CEDCClientUIInterface::MSG_WARNING);
}
