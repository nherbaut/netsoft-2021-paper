#!/usr/bin/env python3

import time
import requests
import numpy as np
from requests.auth import HTTPBasicAuth
import apscheduler
from apscheduler.schedulers.blocking import BlockingScheduler
import time


import datetime
import argparse

parser = argparse.ArgumentParser(description='Conformance checking mgt-orders')

parser.add_argument('--seed', '-s', type=int,
                    help='seed for the random generation', default=236346)
parser.add_argument('--la', '-l', type=int,
                    help='mean time between event arrival', default=10)

args = parser.parse_args()


np.random.seed(args.seed)

l=args.la

hosts = {h["id"]: True if np.random.rand()>0.99 else False for h in
         requests.get("http://127.0.0.1:8181/onos/v1/hosts", auth=HTTPBasicAuth('onos', 'rocks')).json()[
             "hosts"]}
sched = BlockingScheduler()

now=datetime.datetime.now()

def write_rules():
    with open("/home/nherbaut/intent.txt", "w") as f:
        for k in sorted(list(hosts.keys())):
            if hosts[k]:
                f.write("block %s\n" % k)

def poisson_event( sched=None ):

    k=np.random.choice(list(hosts.keys()))

    hosts[k]=not hosts[k]
    print("%02.2f\t%d" % ((datetime.datetime.now()-now).total_seconds(),len([1 for k,v in hosts.items() if v])))
    write_rules()
    sched.add_job(poisson_event, trigger='date', run_date=datetime.datetime.now() + datetime.timedelta(seconds=np.random.poisson(l)),
                  kwargs={"sched": sched})



poisson_event(sched)


sched.start()

'''
import random
random.seed(2606)
for i in range(1,10):
    to_remove = np.random.choice(hosts, i)
    with open("/home/nherbaut/intent.txt","w") as f:
        for host in to_remove:
            f.write("block %s\n"%host)
    print("blocked "+ str(to_remove) )
    time.sleep(5)
    with open("/home/nherbaut/intent.txt", "w") as f:
        f.write("#all clear")
    print("unblocked " + str(to_remove))
    time.sleep(3)
'''
