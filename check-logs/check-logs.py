#!/usr/bin/env python3
import collections
import argparse
import networkx
import re
from flows import *

parser = argparse.ArgumentParser(description='Conformance checking mgt-orders')
parser.add_argument('--flow-logs', '-f', type=str,
                    help='flow logs file', default="/home/nherbaut/flow-logs")

parser.add_argument('--management-commands', '-m', type=str,
                    help='Management Commands', default="/home/nherbaut/mgt-logs")

parser.add_argument('--host-logs', '-o', type=str,
                    help='Hosts logs', default="/home/nherbaut/host-logs")

parser.add_argument('--timestamp', type=str, help="timestamp for conformance checking", default="[0-9]+")

args = parser.parse_args()

host_logs = collections.defaultdict(dict)
with open(args.host_logs) as f:
    lines = f.readlines()
    for i in range(0, len(lines)):
        line = lines[i]
        match = re.findall("^(%s)\t((?:[0-9]{2}:?){6})\tof:([0-9a-f]+)$" % args.timestamp, line)
        if (len(match) == 0):
            continue
        timestamp, host_mac, device_id = match[0]
        host_logs[timestamp][host_mac] = device_id

mgt_rules = {}
with open(args.management_commands) as f:
    lines = f.readlines()

    for i in range(0, len(lines)):
        line = lines[i]
        match = re.findall("^([0-9]+)\tUPDATE", line)
        if (len(match) == 0):
            continue

        latest = match[0]
        mgt_rules[latest] = (set(), set())
        for j in range(i + 1, len(lines)):
            line = lines[j]
            match = re.findall("^%s\tblock ((?:[0-9]{2}:?){6})/None" % latest, line)
            if len(match) > 0:
                mgt_rules[latest][0].add(match[0])
                continue
            match = re.findall("^%s\tblock-from-to ((?:[0-9]{2}:?){6})/None ((?:[0-9]{2}:?){6})/None" % latest, line)
            if len(match) > 0:
                match = match[0]
                mgt_rules[latest][1].add((match[0], match[1]))
                continue
            break

mgt_rules_timestamps = sorted(mgt_rules.keys())

flow_logs = collections.defaultdict(list)

with open(args.flow_logs, "r") as f:
    for line in f.readlines():

        drop_data = re.findall(
            "(%s)\tof:([0-9a-f]+)\tto:((?:[0-9]{2}:?){6}),from:((?:[0-9]{2}:?){6})\tDROP" % args.timestamp, line)
        if (drop_data is not None and len(drop_data) > 0):
            drop_data = drop_data[0]
            flow_logs[drop_data[0]].append(DropFlowLog(drop_data[0], drop_data[1], drop_data[2], drop_data[3], "DROP"))
            continue
        drop_data = re.findall("^(%s)\tof:([0-9a-f]+)\tto:((?:[0-9]{2}:?){6})\tDROP" % args.timestamp, line)
        if (drop_data is not None and len(drop_data) > 0):
            drop_data = drop_data[0]
            flow_logs[drop_data[0]].append(DropFlowLog(drop_data[0], drop_data[1], None, drop_data[2], "DROP"))
            continue
        drop_data = re.findall("^(%s)\tof:([0-9a-f]+)\tfrom:((?:[0-9]{2}:?){6})\tDROP" % args.timestamp, line)
        if (drop_data is not None and len(drop_data) > 0):
            drop_data = drop_data[0]
            flow_logs[drop_data[0]].append(DropFlowLog(drop_data[0], drop_data[1], drop_data[2], None, "DROP"))
            continue
        output_data = re.findall(
            "^(%s)\tof:([0-9a-f]+)\tto:((?:[0-9]{2}:?){6}),from:((?:[0-9]{2}:?){6})\tOUTPUT:of:([0-9a-f]+)$" % args.timestamp,
            line)
        if (output_data is not None and len(output_data) > 0):
            output_data = output_data[0]
            flow_logs[output_data[0]].append(
                OutputFlowLog(output_data[0], output_data[1], output_data[3], output_data[2], output_data[4]))


def get_mgt_rulesfor_timestamp(k, mgt_rules):
    command_timestamps = sorted(mgt_rules.keys())
    prev = command_timestamps[0]
    for i in sorted(mgt_rules.keys()):
        if i > k:
            break
        else:
            prev = i
    return prev, mgt_rules[prev]


class DroppedOnPathException(Exception):
    pass


class NextDeviceOnPathAbsentException(Exception):
    pass


for timestamp in flow_logs.keys():
    results = []
    g = networkx.Graph()
    print("checkt conformance for timestamp %s" % timestamp)
    for ts, hosts in [(kk, vv) for kk, vv in flow_logs.items() if kk == timestamp]:
        t, rules = get_mgt_rulesfor_timestamp(ts, mgt_rules)
        g = networkx.Graph()
        for log in [vv for vv in hosts if isinstance(vv, OutputFlowLog)]:
            if (log.deviceId, log.output_action) in g.edges:
                g.edges[(log.deviceId, log.output_action)]["flow"].append(log)
            else:
                g.add_edge(log.deviceId, log.output_action, flow=[log])
        for log in [vv for vv in hosts if isinstance(vv, DropFlowLog)]:
            if log.deviceId in g.nodes:
                if "flow" in g.nodes[log.deviceId]:
                    g.nodes[log.deviceId]["flow"].append(log)
                    continue
            g.add_node(log.deviceId, flow=[log])

    for ts, hosts in [(kk, vv) for kk, vv in host_logs.items() if kk == timestamp]:
        for mac, device_id in hosts.items():
            g.add_edge(mac, device_id,
                       flow=[OutputFlowLog(ts, mac, None, None, device_id),
                             OutputFlowLog(ts, device_id, None, None, mac)])

            g.add_node(mac, flow=[])

    hosts_mac = sorted([h for h in hosts.keys()])
    fault_counts = 0
    for host1, host2 in [(aa, bb) for aa in hosts_mac for bb in hosts_mac if aa != bb and aa < bb]:

        packet = EthPacket(host1, host2)
        #print("\tchecking connectivity for %s %s" % (host1, host2))
        for path in networkx.algorithms.all_simple_paths(g, host1, host2):
            #print("candidate: %s"%path)
            try:
                for src, dst in zip(path, path[1:]):
                    for src_flow in g.nodes[src].get("flow", []):
                        if src_flow.isDropping(packet):
                            raise DroppedOnPathException()
                    for dst_flow in g.nodes[dst].get("flow", []):
                        if dst_flow.isDropping(packet):
                            raise DroppedOnPathException()

                    valid_flow_output = False
                    for output_flow in g.edges[(src, dst)]["flow"]:
                        if output_flow.get_next_device(packet.src, packet.dst) == dst:
                            valid_flow_output = True
                            #print("%s %s ok"%(src,dst))
                            break
                    if not valid_flow_output:

                        raise NextDeviceOnPathAbsentException()
                break
            except (NextDeviceOnPathAbsentException, DroppedOnPathException) as e:
                #print("%s %s ko" % (src, dst))
                #print("trying another path")
                continue
            break  # success!
        else:
            results.append((host1, host2, False))
            continue
        results.append((host1, host2, True))

    #print("%s (%d/%d)" % (timestamp, len([res for _, _, res in results if res]), len(results)))
    for h1, h2, res in results:
        print("\t%s %s %s" % (h1, h2, u"\u2713" if res else u"\u2718"))
