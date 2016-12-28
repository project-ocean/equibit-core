// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <stdint.h>
#include <functional>

namespace edc
{
const int DEFAULT_HTTP_THREADS=4;
const int DEFAULT_HTTP_WORKQUEUE=16;
const int DEFAULT_HTTP_SERVER_TIMEOUT=30;
}

struct evhttp_request;
struct event_base;
class CService;
class EDCHTTPRequest;

/** Initialize HTTP server.
 * Call this before RegisterHTTPHandler or EventBase().
 */
bool edcInitHTTPServer();

/** Start HTTP server.
 * This is separate from InitHTTPServer to give users race-condition-free time
 * to register their handlers between InitHTTPServer and StartHTTPServer.
 */
bool edcStartHTTPServer();

/** Interrupt HTTP server threads */
void edcInterruptHTTPServer();

/** Stop HTTP server */
void edcStopHTTPServer();

/** Handler for requests to a certain HTTP path */
typedef std::function<bool(EDCHTTPRequest* req, const std::string &)> EDCHTTPRequestHandler;

/** Register handler for prefix.
 * If multiple handlers match a prefix, the first-registered one will
 * be invoked.
 */
void edcRegisterHTTPHandler(const std::string &prefix, bool exactMatch, const EDCHTTPRequestHandler &handler);

/** Unregister handler for prefix */
void edcUnregisterHTTPHandler(const std::string &prefix, bool exactMatch);

/** In-flight HTTP request.
 * Thin C++ wrapper around evhttp_request.
 */
class EDCHTTPRequest
{
private:
    struct evhttp_request* req;
    bool replySent;

public:
    EDCHTTPRequest(struct evhttp_request* req);
    ~EDCHTTPRequest();

    enum RequestMethod 
	{
        UNKNOWN,
        GET,
        POST,
        HEAD,
        PUT
    };

    /** Get requested URI.
     */
    std::string GetURI();

    /** Get CService (address:ip) for the origin of the http request.
     */
    CService GetPeer();

    /** Get request method.
     */
    RequestMethod GetRequestMethod();

    /**
     * Get the request header specified by hdr, or an empty string.
     * Return an pair (isPresent,string).
     */
    std::pair<bool, std::string> GetHeader(const std::string& hdr);

    /**
     * Read request body.
     *
     * @note As this consumes the underlying buffer, call this only once.
     * Repeated calls will return an empty string.
     */
    std::string ReadBody();

    /**
     * Write output header.
     *
     * @note call this before calling WriteErrorReply or Reply.
     */
    void WriteHeader(const std::string& hdr, const std::string& value);

    /**
     * Write HTTP reply.
     * nStatus is the HTTP status code to send.
     * strReply is the body of the reply. Keep it empty to send a standard message.
     *
     * @note Can be called only once. As this will give the request back to the
     * main thread, do not call any other EDCHTTPRequest methods after calling this.
     */
    void WriteReply(int nStatus, const std::string& strReply = "");
};

/** Event handler closure.
 */
class EDCHTTPClosure
{
public:
    virtual void operator()() = 0;
    virtual ~EDCHTTPClosure() {}
};

/** Event class. This can be used either as an cross-thread trigger or as a timer.
 */
class EDCHTTPEvent
{
public:
    /** Create a new event.
     * deleteWhenTriggered deletes this event object after the event is triggered (and the handler called)
     * handler is the handler to call when the event is triggered.
     */
    EDCHTTPEvent(struct event_base* base, bool deleteWhenTriggered, const std::function<void(void)>& handler);
    ~EDCHTTPEvent();

    /** Trigger the event. If tv is 0, trigger it immediately. Otherwise trigger it after
     * the given time has elapsed.
     */
    void trigger(struct timeval* tv);

    bool deleteWhenTriggered;
    std::function<void(void)> handler;
private:
    struct event* ev;
};
