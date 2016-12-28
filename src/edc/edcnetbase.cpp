// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef HAVE_CONFIG_H
#include "config/bitcoin-config.h"
#endif

#include "edcnetbase.h"
#include "edcparams.h"
#include "edcutil.h"

#include "hash.h"
#include "sync.h"
#include "uint256.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#ifdef HAVE_GETADDRINFO_A
#include <netdb.h>
#endif

#ifndef WIN32
#if HAVE_INET_PTON
#include <arpa/inet.h>
#endif
#include <fcntl.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/thread.hpp>

#if !defined(HAVE_MSG_NOSIGNAL) && !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif


std::string Socks5ErrorString(int err);


namespace
{

proxyType proxyInfo[NET_MAX];
proxyType nameProxy;
CCriticalSection cs_proxyInfos;

// Need ample time for negotiation for very slow proxies such as Tor (milliseconds)
const int SOCKS5_RECV_TIMEOUT = 20 * 1000;

/**
 * Read bytes from socket. This will either read the full number of bytes requested
 * or return False on error or timeout.
 * This function can be interrupted by boost thread interrupt.
 *
 * @param data Buffer to receive into
 * @param len  Length of data to receive
 * @param timeout  Timeout in milliseconds for receive operation
 *
 * @note This function requires that hSocket is in non-blocking mode.
 */
bool static InterruptibleRecv(
	  char * data, 
	  size_t len, 
		 int timeout, 
	SOCKET & hSocket )
{
    int64_t curTime = GetTimeMillis();
    int64_t endTime = curTime + timeout;

    // Maximum time to wait in one select call. It will take up until this 
	// time (in millis) to break off in case of an interruption.
    const int64_t maxWait = 1000;
    while (len > 0 && curTime < endTime) 
	{
        ssize_t ret = recv(hSocket, data, len, 0); // Optimistically try the recv first
        if (ret > 0) 
		{
            len -= ret;
            data += ret;
        } 
		else if (ret == 0) 
		{ 
			// Unexpected disconnection
            return false;
        } 
		else 
		{ 
			// Other error or blocking
            int nErr = WSAGetLastError();
            if (nErr == WSAEINPROGRESS || 
				nErr == WSAEWOULDBLOCK || 
				nErr == WSAEINVAL) 
			{
                if (!IsSelectableSocket(hSocket)) 
				{
                    return false;
                }

                struct timeval tval = MillisToTimeval(std::min(endTime - 
					curTime, maxWait));
                fd_set fdset;
                FD_ZERO(&fdset);
                FD_SET(hSocket, &fdset);
                int nRet = select(hSocket + 1, &fdset, NULL, NULL, &tval);

                if (nRet == SOCKET_ERROR) 
				{
                    return false;
                }
            } 
			else 
			{
                return false;
            }
        }

        boost::this_thread::interruption_point();
        curTime = GetTimeMillis();
    }
    return len == 0;
}

struct ProxyCredentials
{
    std::string username;
    std::string password;
};

/** Connect using SOCKS5 (as described in RFC1928) */
bool Socks5(
		 const std::string & strDest, 
						 int port, 
	const ProxyCredentials * auth, 
					SOCKET & hSocket)
{
    edcLogPrint("net", "SOCKS5 connecting %s\n", strDest);

    if (strDest.size() > 255) 
	{
        CloseSocket(hSocket);
        return error("Hostname too long");
    }

    // Accepted authentication methods
    std::vector<uint8_t> vSocks5Init;
    vSocks5Init.push_back(0x05);

    if (auth) 
	{
        vSocks5Init.push_back(0x02); // # METHODS
        vSocks5Init.push_back(0x00); // X'00' NO AUTHENTICATION REQUIRED
        vSocks5Init.push_back(0x02); // X'02' USERNAME/PASSWORD (RFC1929)
    } 
	else 
	{
        vSocks5Init.push_back(0x01); // # METHODS
        vSocks5Init.push_back(0x00); // X'00' NO AUTHENTICATION REQUIRED
    }

    ssize_t ret = send(hSocket, (const char*)begin_ptr(vSocks5Init), vSocks5Init.size(), MSG_NOSIGNAL);
    if (ret != (ssize_t)vSocks5Init.size()) 
	{
        CloseSocket(hSocket);
        return error("Error sending to proxy");
    }

    char pchRet1[2];
    if (!InterruptibleRecv(pchRet1, 2, SOCKS5_RECV_TIMEOUT, hSocket)) 
	{
        CloseSocket(hSocket);
        edcLogPrintf("Socks5() connect to %s:%d failed: InterruptibleRecv() timeout or other failure\n", strDest, port);
        return false;
    }

    if (pchRet1[0] != 0x05) 
	{
        CloseSocket(hSocket);
        return error("Proxy failed to initialize");
    }

    if (pchRet1[1] == 0x02 && auth) 
	{
        // Perform username/password authentication (as described in RFC1929)
        std::vector<uint8_t> vAuth;
        vAuth.push_back(0x01);

        if (auth->username.size() > 255 || auth->password.size() > 255)
            return error("Proxy username or password too long");

        vAuth.push_back(auth->username.size());
        vAuth.insert(vAuth.end(), auth->username.begin(), auth->username.end());
        vAuth.push_back(auth->password.size());
        vAuth.insert(vAuth.end(), auth->password.begin(), auth->password.end());
        ret = send(hSocket, (const char*)begin_ptr(vAuth), vAuth.size(), MSG_NOSIGNAL);

        if (ret != (ssize_t)vAuth.size()) 
		{
            CloseSocket(hSocket);
            return error("Error sending authentication to proxy");
        }

        edcLogPrint("proxy", "SOCKS5 sending proxy authentication %s:%s\n", 
			auth->username, auth->password);

        char pchRetA[2];
        if (!InterruptibleRecv(pchRetA, 2, SOCKS5_RECV_TIMEOUT, hSocket)) 
		{
            CloseSocket(hSocket);
            return error("Error reading proxy authentication response");
        }

        if (pchRetA[0] != 0x01 || pchRetA[1] != 0x00) 
		{
            CloseSocket(hSocket);
            return error("Proxy authentication unsuccessful");
        }
    } 
	else if (pchRet1[1] == 0x00) 
	{
        // Perform no authentication
    } 
	else 
	{
        CloseSocket(hSocket);
        return error("Proxy requested wrong authentication method %02x", 
			pchRet1[1]);
    }

    std::vector<uint8_t> vSocks5;

    vSocks5.push_back(0x05); // VER protocol version
    vSocks5.push_back(0x01); // CMD CONNECT
    vSocks5.push_back(0x00); // RSV Reserved
    vSocks5.push_back(0x03); // ATYP DOMAINNAME
    vSocks5.push_back(strDest.size()); // Length<=255 is checked at beginning of function
    vSocks5.insert(vSocks5.end(), strDest.begin(), strDest.end());
    vSocks5.push_back((port >> 8) & 0xFF);
    vSocks5.push_back((port >> 0) & 0xFF);
    ret = send(hSocket, (const char*)begin_ptr(vSocks5), vSocks5.size(), 
		MSG_NOSIGNAL);

    if (ret != (ssize_t)vSocks5.size()) 
	{
        CloseSocket(hSocket);
        return error("Error sending to proxy");
    }

    char pchRet2[4];
    if (!InterruptibleRecv(pchRet2, 4, SOCKS5_RECV_TIMEOUT, hSocket)) 
	{
        CloseSocket(hSocket);
        return error("Error reading proxy response");
    }
    if (pchRet2[0] != 0x05) 
	{
        CloseSocket(hSocket);
        return error("Proxy failed to accept request");
    }
    if (pchRet2[1] != 0x00) 
	{
		// Failures to connect to a peer that are not proxy errors
        CloseSocket(hSocket);
		edcLogPrintf("Socks5() connect to %s:%d failed: %s\n", strDest, port, Socks5ErrorString(pchRet2[1]));
		return false;
    }

    if (pchRet2[2] != 0x00) 
	{
        CloseSocket(hSocket);
        return error("Error: malformed proxy response");
    }
    char pchRet3[256];
    switch (pchRet2[3])
    {
        case 0x01: ret = InterruptibleRecv(pchRet3, 4, SOCKS5_RECV_TIMEOUT, hSocket); break;
        case 0x04: ret = InterruptibleRecv(pchRet3, 16, SOCKS5_RECV_TIMEOUT, hSocket); break;
        case 0x03:
        {
            ret = InterruptibleRecv(pchRet3, 1, SOCKS5_RECV_TIMEOUT, hSocket);
            if (!ret) 
			{
                CloseSocket(hSocket);
                return error("Error reading from proxy");
            }
            int nRecv = pchRet3[0];
            ret = InterruptibleRecv(pchRet3, nRecv, SOCKS5_RECV_TIMEOUT, hSocket);
            break;
        }
        default: CloseSocket(hSocket); return error("Error: malformed proxy response");
    }

    if (!ret) 
	{
        CloseSocket(hSocket);
        return error("Error reading from proxy");
    }

    if (!InterruptibleRecv(pchRet3, 2, SOCKS5_RECV_TIMEOUT, hSocket)) 
	{
        CloseSocket(hSocket);
        return error("Error reading from proxy");
    }
    edcLogPrint("net", "SOCKS5 connected %s\n", strDest);
    return true;
}

bool ConnectSocketDirectly(
	const CService & addrConnect, 
			SOCKET & hSocketRet, 
				 int nTimeout)
{
    hSocketRet = INVALID_SOCKET;

    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrConnect.GetSockAddr((struct sockaddr*)&sockaddr, &len)) 
	{
        edcLogPrintf("Cannot connect to %s: unsupported network\n", 
			addrConnect.ToString());
        return false;
    }

    SOCKET hSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET)
        return false;

    int set = 1;
#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
#endif

    //Disable Nagle's algorithm
#ifdef WIN32
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
#else
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&set, sizeof(int));
#endif

    // Set to non-blocking
    if (!SetSocketNonBlocking(hSocket, true))
        return error("ConnectSocketDirectly: Setting socket to non-blocking failed, error %s\n", NetworkErrorString(WSAGetLastError()));

    if (connect(hSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        // WSAEINVAL is here because some legacy version of winsock uses it
        if (nErr == WSAEINPROGRESS || nErr == WSAEWOULDBLOCK || nErr == WSAEINVAL)
        {
            struct timeval timeout = MillisToTimeval(nTimeout);
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(hSocket, &fdset);
            int nRet = select(hSocket + 1, NULL, &fdset, NULL, &timeout);

            if (nRet == 0)
            {
                edcLogPrint("net", "connection to %s timeout (%d)\n", addrConnect.ToString(), 
					nTimeout );
                CloseSocket(hSocket);
                return false;
            }
            if (nRet == SOCKET_ERROR)
            {
                edcLogPrintf("select() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                CloseSocket(hSocket);
                return false;
            }
            socklen_t nRetSize = sizeof(nRet);
#ifdef WIN32
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, (char*)(&nRet), &nRetSize) == SOCKET_ERROR)
#else
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, &nRet, &nRetSize) == SOCKET_ERROR)
#endif
            {
                edcLogPrintf("getsockopt() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                CloseSocket(hSocket);
                return false;
            }
            if (nRet != 0)
            {
                edcLogPrintf("connect() to %s failed after select(): %s\n", addrConnect.ToString(), NetworkErrorString(nRet));
                CloseSocket(hSocket);
                return false;
            }
        }
#ifdef WIN32
        else if (WSAGetLastError() != WSAEISCONN)
#else
        else
#endif
        {
            edcLogPrintf("connect() to %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
            CloseSocket(hSocket);
            return false;
        }
    }

    hSocketRet = hSocket;
    return true;
}

bool ConnectThroughProxy(
	  const proxyType & proxy, 
	const std::string & strDest, 
					int port, 
			   SOCKET & hSocketRet, 
					int nTimeout, 
				 bool * outProxyConnectionFailed)
{
    SOCKET hSocket = INVALID_SOCKET;

    // first connect to proxy server
    if (!ConnectSocketDirectly(proxy.proxy, hSocket, nTimeout)) 
	{
        if (outProxyConnectionFailed)
            *outProxyConnectionFailed = true;
        return false;
    }

    // do socks negotiation
    if (proxy.randomize_credentials) 
	{
        ProxyCredentials random_auth;
        random_auth.username = strprintf("%i", insecure_rand());
        random_auth.password = strprintf("%i", insecure_rand());

        if (!Socks5(strDest, (unsigned short)port, &random_auth, hSocket))
            return false;
    } 
	else 
	{
        if (!Socks5(strDest, (unsigned short)port, 0, hSocket))
            return false;
    }

    hSocketRet = hSocket;
    return true;
}

}

bool edcSetProxy(enum Network net, const proxyType &addrProxy) 
{
    assert(net >= 0 && net < NET_MAX);
    if (!addrProxy.IsValid())
        return false;
    LOCK(cs_proxyInfos);
    proxyInfo[net] = addrProxy;
    return true;
}

bool edcGetProxy(enum Network net, proxyType &proxyInfoOut) 
{
    assert(net >= 0 && net < NET_MAX);
    LOCK(cs_proxyInfos);
    if (!proxyInfo[net].IsValid()) 
        return false;
    proxyInfoOut = proxyInfo[net];
    return true;
}

bool edcSetNameProxy(const proxyType &addrProxy) 
{
    if (!addrProxy.IsValid())
        return false;
    LOCK(cs_proxyInfos);
    nameProxy = addrProxy;
    return true;
}

bool edcGetNameProxy(proxyType &nameProxyOut) 
{
    LOCK(cs_proxyInfos);
    if(!nameProxy.IsValid())
        return false;
    nameProxyOut = nameProxy;
    return true;
}

bool edcHaveNameProxy() 
{
    LOCK(cs_proxyInfos); 
    return nameProxy.IsValid();
}

bool edcIsProxy(const CNetAddr &addr) 
{
    LOCK(cs_proxyInfos);
    for (int i = 0; i < NET_MAX; i++) 
	{
        if (addr == (CNetAddr)proxyInfo[i].proxy)
            return true;
    }
    return false;
}

bool edcConnectSocket(
	const CService & addrDest, 
			SOCKET & hSocketRet, 
				 int nTimeout, 
			  bool * outProxyConnectionFailed)
{
    proxyType proxy;
    if (outProxyConnectionFailed)
        *outProxyConnectionFailed = false;

    if (edcGetProxy(addrDest.GetNetwork(), proxy)) // KEEP
        return ConnectThroughProxy(proxy, addrDest.ToStringIP(), addrDest.GetPort(), hSocketRet, nTimeout, outProxyConnectionFailed);
    else // no proxy needed (none set for target network)
        return ConnectSocketDirectly(addrDest, hSocketRet, nTimeout);
}

bool edcConnectSocketByName(
	  CService & addr, 
		SOCKET & hSocketRet, 
	const char * pszDest, 
			 int portDefault, 
			 int nTimeout, 
		  bool * outProxyConnectionFailed)
{
	EDCparams & params = EDCparams::singleton();

    std::string strDest;
    int port = portDefault;

    if (outProxyConnectionFailed)
        *outProxyConnectionFailed = false;

    SplitHostPort(std::string(pszDest), port, strDest);

    proxyType proxy;
    edcGetNameProxy(proxy);

    std::vector<CService> addrResolved;
    if (Lookup(strDest.c_str(), addrResolved, port, params.dns && 
	!edcHaveNameProxy(), 256)) 
	{
        if (addrResolved.size() > 0) 
		{
            addr = addrResolved[GetRand(addrResolved.size())];


            return edcConnectSocket(addr, hSocketRet, nTimeout);
        }
    }

    addr = CService();

    if (!edcHaveNameProxy())
        return false;
    return ConnectThroughProxy(proxy, strDest, port, hSocketRet, nTimeout, outProxyConnectionFailed);
}
