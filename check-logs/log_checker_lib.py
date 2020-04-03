import logging
import os
import re
from collections import __init__
import collections
import networkx

from flows import DropFlowLog, OutputFlowLog, EthPacket

check_src="00:00:00:00:00:00"
check_dst="00:00:00:00:00:00"


def get_flow_logs(flow_logs_file):
    flow_logs = collections.defaultdict(list)
    with open(flow_logs_file, "r") as f:
        for line in f.readlines():

            drop_data = re.findall(
                "(%s)\tof:([0-9a-fA-F]+)\tto:((?:[0-9a-fA-F]{2}:?){6}),from:((?:[0-9a-fA-F]{2}:?){6})\tDROP",
                line)
            if (drop_data is not None and len(drop_data) > 0):
                drop_data = drop_data[0]
                flow_logs[drop_data[0]].append(
                    DropFlowLog(drop_data[0], drop_data[1], drop_data[2], drop_data[3], "DROP"))
                continue
            drop_data = re.findall("^([0-9]+)\tof:([0-9a-fA-F]+)\tto:((?:[0-9a-fA-F]{2}:?){6})\tDROP",
                                   line)
            if (drop_data is not None and len(drop_data) > 0):
                drop_data = drop_data[0]
                flow_logs[drop_data[0]].append(DropFlowLog(drop_data[0], drop_data[1], None, drop_data[2], "DROP"))
                continue
            drop_data = re.findall("^([0-9]+)\tof:([0-9a-fA-F]+)\tfrom:((?:[0-9a-fA-F]{2}:?){6})\tDROP",
                                   line)
            if (drop_data is not None and len(drop_data) > 0):
                drop_data = drop_data[0]
                flow_logs[drop_data[0]].append(DropFlowLog(drop_data[0], drop_data[1], drop_data[2], None, "DROP"))
                continue
            output_data = re.findall(
                "^([0-9]+)\tof:([0-9a-fA-F]+)\tto:((?:[0-9a-fA-F]{2}:?){6}),from:((?:[0-9a-fA-F]{2}:?){6})\tOUTPUT:(of|mac):([0-9a-fA-F:af]+)$",
                line)
            if (output_data is not None and len(output_data) > 0):
                output_data = output_data[0]
                flow_logs[output_data[0]].append(
                    OutputFlowLog(output_data[0], output_data[1], output_data[3], output_data[2], output_data[5],
                                  True if output_data[4] == 'mac' else False))
    return flow_logs


def get_mgt_logs(management_commands):
    mgt_rules = {}
    with open(management_commands) as f:
        lines = f.readlines()

        for i in range(0, len(lines)):
            line = lines[i]
            match = re.findall("^([0-9a-fA-F]+)\tUPDATE$", line)
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
                match = re.findall(
                    "^%s\tblock-from-to ((?:[0-9a-fA-F]{2}:?){6})/None ((?:[0-9a-fA-F]{2}:?){6})/None" % latest,
                    line)
                if len(match) > 0:
                    match = match[0]
                    mgt_rules[latest][1].add((match[0], match[1]))
                    mgt_rules[latest][1].add((match[1], match[0]))
                    continue
                break
    return mgt_rules


def generate_flow_graph(flow_logs, timestamp):
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
                graph_src = log.deviceId
                graph_dst = log.output_action

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
    return g


def add_host_graph_nodes(g, host_logs,  timestamp):
    for ts, macs in [(kk, vv) for kk, vv in host_logs.items() if kk == timestamp]:
        for mac, device_id in macs.items():
            g.add_edge(mac, device_id, flow=[OutputFlowLog(timestamp, device_id, mac, None, device_id, False)])

            g.add_node(mac, flow=[])


def generate_connectivity_from_flow(g, hosts_mac):
    results = []
    for host1, host2 in [(aa, bb) for aa in hosts_mac for bb in hosts_mac if aa != bb]:
        if not should_check_connectivity(host1, host2):
            continue
        trace = ""
        packet = EthPacket(host1, host2)
        trace += "\tchecking connectivity for %s %s\n" % (host1, host2)
        for path in sorted(networkx.algorithms.all_simple_paths(g, host1, host2), key=lambda x: len(x)):
            trace += "\t\tcandidate: %s\n" % path
            try:
                for src, dst in zip(path, path[1:]):
                    for src_flow in g.nodes[src].get("flow", []):
                        if src_flow.isDropping(packet):
                            raise DroppedOnPathException()
                    for dst_flow in g.nodes[dst].get("flow", []):
                        if dst_flow.isDropping(packet):
                            raise DroppedOnPathException()
                    for edge_flow in g.edges[(src, dst)].get("flow", []):
                        if (isinstance(edge_flow, DropFlowLog)):
                            if edge_flow.isDropping(packet):
                                raise DroppedOnPathException()

                    valid_flow_output = False
                    for output_flow in g.edges[(src, dst)]["flow"]:
                        next_device_or_host = output_flow.get_next_device(packet.src, packet.dst)
                        if next_device_or_host == dst:
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
    return results


def generate_conformance_results(results, rules,verbose=False):
    all_success = True
    fault_count = 0
    for h1, h2, can_talk in results:
        success = True

        if can_talk:
            if h1 in rules[0] or h2 in rules[0] or (h1, h2) in rules[1] or (h2, h1) in rules[1]:
                if verbose:
                    logging.warning("\t %s and %s should not communicate \u2718" % (h1, h2))
                success = False
        else:
            if not (h1 in rules[0] or h2 in rules[0] or (h1, h2) in rules[1] or (h2, h1) in rules[1]):
                if verbose:
                    logging.warning("\t %s and %s should communicate \u2718" % (h1, h2))
                success = False
        if not success:
            fault_count += 1
            # print("\t%s %s %s" % (h1, h2, u"\u2713" if success else u"\u2718"))
            all_success = False
    return all_success, fault_count


def display_conformance_results(all_success, fault_count, results, timestamp):
    if len(results) > 0:
        return "Conformance at %s : %s \t fault_ratio=%3.2f %% \tblocked=%d\tconnected=%d" % (
            timestamp, u"\u2713" if all_success else u"\u2718", 100 * fault_count / len(results),
            len([r for r in results if not r[2]]), len([r for r in results if r[2]]))
    else:
        return "nothing to check"


def get_host_logs(host_logs_file):
    host_logs = collections.defaultdict(dict)
    with open(host_logs_file) as f:
        lines = f.readlines()
        for i in range(0, len(lines)):
            line = lines[i]
            match = re.findall("^([0-9]+)\t((?:[0-9a-fA-F]{2}:?){6})\tof:([0-9a-fA-F]+)$", line)
            if (len(match) == 0):
                continue
            timestamp, host_mac, device_id = match[0]
            host_logs[timestamp][host_mac] = device_id
    return host_logs


def get_mgt_rules_for_timestamp(k, mgt_rules):
    command_timestamps = sorted(mgt_rules.keys())
    prev = command_timestamps[0]
    for i in sorted(mgt_rules.keys()):
        if i > k:
            break
        else:
            prev = i
    return mgt_rules[prev]


def should_check_connectivity(src, dst):
    if (check_src == VOID_MAC and check_dst == VOID_MAC):
        return True
    elif src == check_src and dst == check_dst:
        return True
    else:
        return False


class DroppedOnPathException(Exception):
    pass


class NextDeviceOnPathAbsentException(Exception):
    pass


def get_log_files(logs_dir):
    return {"".join((p[0][1:].split("/")[-3:])): [os.path.join(p[0], ff) for ff in p[2]] for p in
            os.walk(logs_dir) if len(p[2]) > 0}


MAC_PAIR_RE = r"^((?:[0-9a-fA-F]{2}:?){6}) ((?:[0-9a-fA-F]{2}:?){6})$"
VOID_MAC = "00:00:00:00:00:00"