#!/usr/bin/env python3
import logging
import sys
import collections
import argparse
import networkx
import re
from flows import *

logging.basicConfig(filename='check-logs.log', level=logging.WARNING)
logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

MAC_PAIR_RE = r"^((?:[0-9a-fA-F]{2}:?){6}) ((?:[0-9a-fA-F]{2}:?){6})$"
VOID_MAC = "00:00:00:00:00:00"


def re_type(arg_value, pat=re.compile(MAC_PAIR_RE)):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError
    return arg_value


parser = argparse.ArgumentParser(description='Conformance checking mgt-orders')
parser.add_argument('--flow-logs', '-f', type=str,
                    help='flow logs file', default="/home/nherbaut/flow-logs")

parser.add_argument('--management-commands', '-m', type=str,
                    help='Management Commands', default="/home/nherbaut/mgt-logs")

parser.add_argument('--host-logs', '-o', type=str,
                    help='Hosts logs', default="/home/nherbaut/host-logs")

parser.add_argument('--timestamp', "-t", type=str, help="timestamp for conformance checking", default="[0-9a-fA-F]+")

parser.add_argument('--verbose', '-v', action='store_true', help="verbose")

parser.add_argument('--check-connectivity', type=re_type, default="00:00:00:00:00:00 00:00:00:00:00:00")
args = parser.parse_args()

check_src, check_dst = re.findall(MAC_PAIR_RE, args.check_connectivity)[0]

def should_check_connectivity(src,dst):
    if(check_src==VOID_MAC and check_dst==VOID_MAC):
        return True
    elif src==check_src and dst==check_dst:
        return True
    else:
        return False



host_logs = collections.defaultdict(dict)
with open(args.host_logs) as f:
    lines = f.readlines()
    for i in range(0, len(lines)):
        line = lines[i]
        match = re.findall("^(%s)\t((?:[0-9a-fA-F]{2}:?){6})\tof:([0-9a-fA-F]+)$" % args.timestamp, line)
        if (len(match) == 0):
            continue
        timestamp, host_mac, device_id = match[0]
        host_logs[timestamp][host_mac] = device_id

mgt_rules = {}
with open(args.management_commands) as f:
    lines = f.readlines()

    for i in range(0, len(lines)):
        line = lines[i]
        match = re.findall("^([0-9a-fA-F]+)\tUPDATE", line)
        if (len(match) == 0):
            continue

        latest = match[0]
        mgt_rules[latest] = (set(), set())
        for j in range(i + 1, len(lines)):
            line = lines[j]
            match = re.findall("^%s\tblock ((?:[0-9a-fA-F]{2}:?){6})/None" % latest, line)
            if len(match) > 0:
                mgt_rules[latest][0].add(match[0])
                continue
            match = re.findall("^%s\tblock-from-to ((?:[0-9a-fA-F]{2}:?){6})/None ((?:[0-9a-fA-F]{2}:?){6})/None" % latest,
                               line)
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
            "(%s)\tof:([0-9a-fA-F]+)\tto:((?:[0-9a-fA-F]{2}:?){6}),from:((?:[0-9a-fA-F]{2}:?){6})\tDROP" % args.timestamp, line)
        if (drop_data is not None and len(drop_data) > 0):
            drop_data = drop_data[0]
            flow_logs[drop_data[0]].append(DropFlowLog(drop_data[0], drop_data[1], drop_data[2], drop_data[3], "DROP"))
            continue
        drop_data = re.findall("^(%s)\tof:([0-9a-fA-F]+)\tto:((?:[0-9a-fA-F]{2}:?){6})\tDROP" % args.timestamp, line)
        if (drop_data is not None and len(drop_data) > 0):
            drop_data = drop_data[0]
            flow_logs[drop_data[0]].append(DropFlowLog(drop_data[0], drop_data[1], None, drop_data[2], "DROP"))
            continue
        drop_data = re.findall("^(%s)\tof:([0-9a-fA-F]+)\tfrom:((?:[0-9a-fA-F]{2}:?){6})\tDROP" % args.timestamp, line)
        if (drop_data is not None and len(drop_data) > 0):
            drop_data = drop_data[0]
            flow_logs[drop_data[0]].append(DropFlowLog(drop_data[0], drop_data[1], drop_data[2], None, "DROP"))
            continue
        output_data = re.findall(
            "^(%s)\tof:([0-9a-fA-F]+)\tto:((?:[0-9a-fA-F]{2}:?){6}),from:((?:[0-9a-fA-F]{2}:?){6})\tOUTPUT:(of|mac):([0-9a-fA-F:af]+)$" % args.timestamp,
            line)
        if (output_data is not None and len(output_data) > 0):
            output_data = output_data[0]
            flow_logs[output_data[0]].append(OutputFlowLog(output_data[0], output_data[1], output_data[3], output_data[2], output_data[5],True if output_data[4]=='mac' else False))



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


for timestamp in sorted(flow_logs.keys()):
    results = []

    g = networkx.Graph()

    for ts, hosts in [(kk, vv) for kk, vv in flow_logs.items() if kk == timestamp]:

        g = networkx.DiGraph()
        for log in [vv for vv in hosts if isinstance(vv, OutputFlowLog)]:
            if log.to_host:

                 if (log.deviceId, log.dl_dst) in g.edges:
                     g.edges[(log.deviceId, log.dl_dst)]["flow"].append(log)
                 else:
                     g.add_edge(log.deviceId, log.dl_dst, flow=[log])

            else:
                graph_src=log.deviceId
                graph_dst=log.output_action

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

    macs = [(kk, vv) for kk, vv in host_logs.items() if kk == timestamp]
    if (len(macs) == 0):
        print("no macs avail for hosts, skipping")
        continue

    for ts, macs in [(kk, vv) for kk, vv in host_logs.items() if kk == timestamp]:
        for mac, device_id in macs.items():

            g.add_edge(mac, device_id,flow=[OutputFlowLog(timestamp,device_id,mac,None,device_id,False)])

            g.add_node(mac, flow=[])

    hosts_mac = sorted([h for h in macs.keys()])
    fault_counts = 0
    for host1, host2 in [(aa, bb) for aa in hosts_mac for bb in hosts_mac if aa != bb and aa < bb]:
        if not should_check_connectivity(host1, host2):
            continue
        trace = ""
        packet = EthPacket(host1, host2)
        trace += "\tchecking connectivity for %s %s\n" % (host1, host2)
        for path in sorted(networkx.algorithms.all_simple_paths(g, host1, host2),key=lambda x:len(x)):
            trace += "\t\tcandidate: %s\n" % path
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
                        next_device_or_host = output_flow.get_next_device(packet.src, packet.dst)
                        if next_device_or_host  == dst:
                            valid_flow_output = True
                            trace += "\t\t%s %s ok\n" % (src, dst)
                            break
                    if not valid_flow_output:
                        raise NextDeviceOnPathAbsentException()
                break
            except (NextDeviceOnPathAbsentException, DroppedOnPathException) as e:
                trace += "\t\t%s %s ko\n" % (src, dst)
                trace += "\t\ttrying another path\n"
                continue
            break  # success!
        else:
            results.append((host1, host2, False))
            trace += "\t\tno path is valid"
            logging.debug(trace)
            continue
        results.append((host1, host2, True))

        trace += "\t\tpath is accepted %s " % (str(path))
        logging.info(trace)

    # print("%s (%d/%d)" % (timestamp, len([res for _, _, res in results if res]), len(results)))

    _, rules = get_mgt_rulesfor_timestamp(timestamp, mgt_rules)
    all_success = True
    fault_count = 0
    if (args.verbose):
        logging.info("Verifying flows for:\n%s" % str(rules))
    for h1, h2, can_talk in results:
        success = True

        if can_talk:
            if h1 in rules[0] or h2 in rules[0] or (h1, h2) in rules[1] or (h2, h1) in rules[1]:
                if args.verbose:
                    logging.warning("\t %s and %s should not communicate \u2718" % (h1, h2))
                success = False
        else:
            if not (h1 in rules[0] or h2 in rules[0] or (h1, h2) in rules[1] or (h2, h1) in rules[1]):
                if args.verbose:
                    logging.warning("\t %s and %s should communicate \u2718" % (h1, h2))
                success = False
        if not success:
            fault_count += 1
            # print("\t%s %s %s" % (h1, h2, u"\u2713" if success else u"\u2718"))
            all_success = False
    if len(results)>0:
        logging.warning("Conformance at %s : %s \t fault_ratio=%3.2f %% \tblocked=%d\tconnected=%d" % (timestamp, u"\u2713" if all_success else u"\u2718", 100*fault_count/len(results),len([r for r in results if not r[2] ]),len([r for r in results if  r[2] ])))
