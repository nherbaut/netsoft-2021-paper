#!/usr/bin/python

import time
import requests
import numpy as np
from requests.auth import HTTPBasicAuth
import random
hosts=[h["id"] for h in requests.get("http://127.0.0.1:8181/onos/v1/hosts",auth=HTTPBasicAuth('onos', 'rocks')).json()["hosts"]]



for i in range(1,10):
    to_remove = np.random.choice(hosts, i)
    with open("/home/nherbaut/intent.txt","w") as f:
        for host in to_remove:
            f.write("block %s\n"%host)
    print("blocked "+ str(to_remove) )
    time.sleep(10)
    with open("/home/nherbaut/intent.txt", "w") as f:
        f.write("#all clear")
    print("unblocked " + str(to_remove))
    time.sleep(5)

