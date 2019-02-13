# Generates a csv of blocktimes suitable for importing into Excel or Google Docs
#
# Depends on https://github.com/jgarzik/python-bitcoinrpc
# pip install python-bitcoinrpc

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from datetime import datetime
from dateutil import tz
import numpy
    
# rpc_user and rpc_password are set in the bitcoin.conf file
rpc_connection = AuthServiceProxy("http://equibit:equibit@127.0.0.1:18331", timeout=120)
best_block_hash = rpc_connection.getbestblockhash()
tip = rpc_connection.getblock(best_block_hash)
#print(tip)

N = 100
min = 0
max = tip["height"]

if max > N:
    min = max - N  

block_times = []
hash_times = []
difficulties = []
txns = []

for height in range(min, max+1):
    i = height-min
    hash = rpc_connection.getblockhash(height)
    block = rpc_connection.getblock(hash)
    block_time = block["time"]
    if height > min:
        hash_time = block_time - block_times[i-1]
        hash_times.append(hash_time)
    else:
        hash_time = 0
    block_times.append(block_time)    
    utc = datetime.utcfromtimestamp(block_time).replace(tzinfo=tz.tzutc())
    timestamp = utc.astimezone(tz.tzlocal()).strftime('%Y-%m-%d %H:%M:%S')
    difficulty = block["difficulty"]
    difficulties.append(difficulty)
    nTx = block["nTx"]
    txns.append(nTx)
    size = block["size"]
    witsize = 100. * (size - block["strippedsize"])/size
    bits = block["bits"]
    hash = block["hash"]
    
    # Get average over last 12 blocks
    if i > 13:
        window = hash_times[i-13:i]
        time_avg = numpy.mean(window)
    else:
        # or if we don't have 12 blocks yet get the running average
        if i > 0:
            window = hash_times[0:i]
            time_avg = numpy.mean(window)
        else:
            time_avg = 0
        
    print('{:>5}, {}, {:>5}, {:8.2f}, {:3.2f}, {}, {:12.2f}, {:4d}, {:8d}, {:4.1f}%, {}'.format(height, timestamp, hash_time, time_avg, time_avg/600, bits, difficulty, nTx, size, witsize, hash[:20]))
  
print("hash times   avg={:.2f} std={:.2f} max={:6d}".format(numpy.mean(hash_times), numpy.std(hash_times), numpy.max(hash_times)))    
print("transactions avg={:.2f} std={:.2f} max={:6d}".format(numpy.mean(txns), numpy.std(txns), numpy.max(txns)))
print("difficulty   avg={:.2E} std={:.2E} max={:.2E}".format(numpy.mean(difficulties), numpy.std(difficulties), numpy.max(difficulties)))
