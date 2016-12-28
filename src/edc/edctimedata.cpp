// Copyright (c) 2014-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "timedata.h"

#include "edcnetbase.h"
#include "sync.h"
#include "edcui_interface.h"
#include "edcutil.h"
#include "utilstrencodings.h"
#include "edcparams.h"

#include <boost/foreach.hpp>

using namespace std;

static CCriticalSection cs_nTimeOffset;
static int64_t nTimeOffset = 0;

/**
 * "Never go to sea with two chronometers; take one or three."
 * Our three time sources are:
 *  - System clock
 *  - Median of other nodes clocks
 *  - The user (asking the user to fix the system clock if the first two disagree)
 */
int64_t edcGetTimeOffset()
{
    LOCK(cs_nTimeOffset);
    return nTimeOffset;
}

int64_t edcGetAdjustedTime()
{
    return GetTime() + edcGetTimeOffset();
}

static int64_t abs64(int64_t n)
{
    return (n >= 0 ? n : -n);
}

#define EQUIBIT_TIMEDATA_MAX_SAMPLES 200

void edcAddTimeData(const CNetAddr& ip, int64_t nOffsetSample)
{
	EDCparams & params = EDCparams::singleton();

    LOCK(cs_nTimeOffset);

    // Ignore duplicates
    static set<CNetAddr> setKnown;
    if (setKnown.size() == EQUIBIT_TIMEDATA_MAX_SAMPLES)
        return;
    if (!setKnown.insert(ip).second)
        return;

    // Add data
    static CMedianFilter<int64_t> vTimeOffsets(EQUIBIT_TIMEDATA_MAX_SAMPLES, 0);
    vTimeOffsets.input(nOffsetSample);
    edcLogPrint("net","added time data, samples %d, offset %+d (%+d minutes)\n", vTimeOffsets.size(), nOffsetSample, nOffsetSample/60);

    // There is a known issue here (see issue #4521):
    //
    // - The structure vTimeOffsets contains up to 200 elements, after which
    // any new element added to it will not increase its size, replacing the
    // oldest element.
    //
    // - The condition to update nTimeOffset includes checking whether the
    // number of elements in vTimeOffsets is odd, which will never happen after
    // there are 200 elements.
    //
    // But in this case the 'bug' is protective against some attacks, and may
    // actually explain why we've never seen attacks which manipulate the
    // clock offset.
    //
    // So we should hold off on fixing this and clean it up as part of
    // a timing cleanup that strengthens it in a number of other ways.
    //
    if (vTimeOffsets.size() >= 5 && vTimeOffsets.size() % 2 == 1)
    {
        int64_t nMedian = vTimeOffsets.median();
        std::vector<int64_t> vSorted = vTimeOffsets.sorted();
        // Only let other nodes change our time by so much
        if (abs64(nMedian) <= std::max<int64_t>(0, params.maxtimeadjustment))
        {
            nTimeOffset = nMedian;
        }
        else
        {
            nTimeOffset = 0;

            static bool fDone;
            if (!fDone)
            {
                // If nobody has a time different than ours but within 5 minutes of ours, give a warning
                bool fMatch = false;
                BOOST_FOREACH(int64_t nOffset, vSorted)
                    if (nOffset != 0 && abs64(nOffset) < 5 * 60)
                        fMatch = true;

                if (!fMatch)
                {
                    fDone = true;
                    string strMessage = strprintf(_("Please check that your computer's date and time are correct! If your clock is wrong, %s will not work properly."), _(PACKAGE_NAME));
                    edcstrMiscWarning = strMessage;
                    edcUiInterface.ThreadSafeMessageBox(strMessage, "", CEDCClientUIInterface::MSG_WARNING);
                }
            }
        }
        
        BOOST_FOREACH(int64_t n, vSorted)
            edcLogPrint("net", "%+d  ", n);
        edcLogPrint("net", "|  ");
        
        edcLogPrint("net", "nTimeOffset = %+d  (%+d minutes)\n", nTimeOffset, nTimeOffset/60);
    }
}
