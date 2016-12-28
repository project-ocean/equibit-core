// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "edcnoui.h"

#include "edcui_interface.h"
#include "edcutil.h"

#include <cstdio>
#include <stdint.h>
#include <string>

namespace
{

bool edcnoui_ThreadSafeMessageBox(
	const std::string & message, 
	const std::string & caption, 
		   unsigned int style)
{
    bool fSecure = style & CEDCClientUIInterface::SECURE;
    style &= ~CEDCClientUIInterface::SECURE;

    std::string strCaption;

    // Check for usage of predefined caption
    switch (style) 
	{
    case CEDCClientUIInterface::MSG_ERROR:
        strCaption += _("Error");
        break;
    case CEDCClientUIInterface::MSG_WARNING:
        strCaption += _("Warning");
        break;
    case CEDCClientUIInterface::MSG_INFORMATION:
        strCaption += _("Information");
        break;
    default:
        strCaption += caption; // Use supplied caption (can be empty)
    }

    if (!fSecure)
        edcLogPrintf("%s: %s\n", strCaption, message);
    fprintf(stderr, "%s: %s\n", strCaption.c_str(), message.c_str());

    return false;
}

bool noui_ThreadSafeQuestion(const std::string& /* ignored interactive message */, const std::string& message, const std::string& caption, unsigned int style)
{
    return edcnoui_ThreadSafeMessageBox(message, caption, style);
}

void edcnoui_InitMessage(const std::string& message)
{
    edcLogPrintf("init message: %s\n", message);
}
}

void edcnoui_connect()
{
    // Connect equibitd signal handlers
    edcUiInterface.ThreadSafeMessageBox.connect(edcnoui_ThreadSafeMessageBox);
	edcUiInterface.ThreadSafeQuestion.connect(noui_ThreadSafeQuestion);
    edcUiInterface.InitMessage.connect(edcnoui_InitMessage);
}
