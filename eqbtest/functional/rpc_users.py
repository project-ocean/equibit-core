#!/usr/bin/env python3
# Copyright (c) 2015-2017 The Bitcoin Core developers
# Copyright (c) 2018 Equibit Group AG
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test multiple RPC users."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import str_to_b64str, assert_equal

import os
import http.client
import urllib.parse

class HTTPBasicsTest (BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_chain(self):
        super().setup_chain()
        #Append rpcauth to ocean.conf before initialization
        rpcauth = "rpcauth=rt:6cbd35b4b23aea78165f7e26e62e5f5$0f441a317017f065a9dd44c7ede4bb6a94b3ddc8a17dbd0af16f18077a1d0a40"
        rpcauth2 = "rpcauth=rt2:e4e328ce391fe68ed92478b722dbb2ea$ab25bff9a3bbe472585f0b2c507979638e3569d7c38b794c56e671be72a95e47"
        rpcuser = "rpcuser=rpcuser💻"
        rpcpassword = "rpcpassword=rpcpassword🔑"
        with open(os.path.join(self.options.tmpdir+"/node0", "ocean.conf"), 'a', encoding='utf8') as f:
            f.write(rpcauth+"\n")
            f.write(rpcauth2+"\n")
        with open(os.path.join(self.options.tmpdir+"/node1", "ocean.conf"), 'a', encoding='utf8') as f:
            f.write(rpcuser+"\n")
            f.write(rpcpassword+"\n")

    def run_test(self):

        ##################################################
        # Check correctness of the rpcauth config option #
        ##################################################
        url = urllib.parse.urlparse(self.nodes[0].url)

        #Old authpair
        authpair = url.username + ':' + url.password

        #New authpair generated via share/rpcuser tool
        password = "knUsEF85BhgSbEv49bNWGIOvwlhxbToMzJFjVUVvP6M="

        #Second authpair with different username
        password2 = "EyMP9AynlRJakmFYazOMzu7u5mLhQBd2mMu8gDmvd8A="
        authpairnew = "rt:"+password

        headers = {"Authorization": "Basic " + str_to_b64str(authpair)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status, 200)
        conn.close()
        
        #Use new authpair to confirm both work
        headers = {"Authorization": "Basic " + str_to_b64str(authpairnew)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status, 200)
        conn.close()

        #Wrong login name with rt's password
        authpairnew = "rtwrong:"+password
        headers = {"Authorization": "Basic " + str_to_b64str(authpairnew)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status, 401)
        conn.close()

        #Wrong password for rt
        authpairnew = "rt:"+password+"wrong"
        headers = {"Authorization": "Basic " + str_to_b64str(authpairnew)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status, 401)
        conn.close()

        #Correct for rt2
        authpairnew = "rt2:"+password2
        headers = {"Authorization": "Basic " + str_to_b64str(authpairnew)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status, 200)
        conn.close()

        #Wrong password for rt2
        authpairnew = "rt2:"+password2+"wrong"
        headers = {"Authorization": "Basic " + str_to_b64str(authpairnew)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status, 401)
        conn.close()

        ###############################################################
        # Check correctness of the rpcuser/rpcpassword config options #
        ###############################################################
        url = urllib.parse.urlparse(self.nodes[1].url)

        # rpcuser and rpcpassword authpair
        rpcuserauthpair = "rpcuser💻:rpcpassword🔑"

        headers = {"Authorization": "Basic " + str_to_b64str(rpcuserauthpair)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status, 200)
        conn.close()

        #Wrong login name with rpcuser's password
        rpcuserauthpair = "rpcuserwrong:rpcpassword"
        headers = {"Authorization": "Basic " + str_to_b64str(rpcuserauthpair)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status, 401)
        conn.close()

        #Wrong password for rpcuser
        rpcuserauthpair = "rpcuser:rpcpasswordwrong"
        headers = {"Authorization": "Basic " + str_to_b64str(rpcuserauthpair)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status, 401)
        conn.close()


if __name__ == '__main__':
    HTTPBasicsTest ().main ()
