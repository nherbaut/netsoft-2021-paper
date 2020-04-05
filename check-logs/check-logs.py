#!/usr/bin/env python3
import sys
import argparse
import time

from log_checker_lib import *
from log_checker_lib import check_dst, check_src
from log_checker_lib import MAC_PAIR_RE
from concurrent.futures import ProcessPoolExecutor

import sys


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


logging.basicConfig(filename='check-logs.log', level=logging.WARNING)
logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))


def re_type(arg_value, pat=re.compile(MAC_PAIR_RE)):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError
    return arg_value


parser = argparse.ArgumentParser(description='Conformance checking mgt-orders')

parser.add_argument('--logs-dir', '-l', type=str,
                    help='flow logs file', default="/home/nherbaut/logs")

parser.add_argument('--management-commands', '-m', type=str,
                    help='Management Commands', default="/home/nherbaut/mgt-logs")

parser.add_argument('--timestamp', "-t", type=str, help="timestamp for conformance checking", default=None)

parser.add_argument('--verbose', '-v', action='store_true', help="verbose")

parser.add_argument("--all", action='store_true', help="check conformance for the entire log serie")

parser.add_argument("--intent", action='store_true', help="use intents for conformance")

parser.add_argument('--check-connectivity', type=re_type, default="00:00:00:00:00:00 00:00:00:00:00:00")

parser.add_argument('--concurrency', type=int, default=10, help="amont of worker process")
args = parser.parse_args()


def intent_baed_connectivity_results(intent_logs_file, host_logs, timestamp):
    hosts_mac = get_hosts_mac(host_logs)
    results = {h1 + h2: [h1, h2, False] for h1 in hosts_mac for h2 in hosts_mac if h1 != h2}
    with open(intent_logs_file, "r") as f:
        for line in f.readlines():
            match = re.findall(
                r"%s\tINSTALLED\t((?:[0-9a-fA-F]{2}:?){6})/None\t((?:[0-9a-fA-F]{2}:?){6})/None" % timestamp,
                line)
            if (len(match) > 0):
                src, dst = match[0]
                results["".join(src + dst)][2] = True
                results["".join(dst + src)][2] = True
    return list(results.values())


def check_conformance(log_item, mgt_logs, verbose, use_intent=False):
    timestamp, logs = log_item
    if timestamp=="1586094549171":
        print("plop")
    topo_logs_file, host_logs_file, flow_logs_file, intent_logs_file = logs
    host_logs = get_host_logs(host_logs_file)


    mgt_instant, mgt_rules = get_mgt_rules_for_timestamp(timestamp, mgt_logs)

    if (not use_intent):
        connectivity_triples = flow_based_connectivity_results(flow_logs_file, host_logs, timestamp)
    else:
        connectivity_triples = intent_baed_connectivity_results(intent_logs_file, host_logs, timestamp)

    security_breach, connectivity_breach = generate_conformance_results(connectivity_triples, mgt_rules, verbose)

    fault_ratio = 100 * (security_breach + connectivity_breach) / len(connectivity_triples)

    # return conformance_results_as_str(all_success, fault_count, connectivity_triples, timestamp)
    return [timestamp, "%2.2f%%" % fault_ratio, security_breach, connectivity_breach,
            len([c for c in connectivity_triples if c[2]]), len([c for c in connectivity_triples if not c[2]])]


def flow_based_connectivity_results(flow_logs_file, host_logs, timestamp):
    flow_logs = get_flow_logs(flow_logs_file)
    g = generate_flow_graph(flow_logs, timestamp)
    add_host_graph_nodes(g, host_logs, timestamp)
    hosts_mac = get_hosts_mac(host_logs)
    results = generate_connectivity_from_flow(g, hosts_mac)
    return results


def get_hosts_mac(host_logs):
    return list(list(host_logs.items())[0][1].keys())


def run_confrmance_monothread(timestamp, mgt_logs, verbose, use_intent, concurrency):

    for log_item_to_analyse in log_itemps_to_analyse:
        result = check_conformance(log_item_to_analyse, mgt_logs, verbose, use_intent)
        print("\t".join([str(rr) for rr in result]))


def run_conformance_multithread(timestamp, mgt_logs, verbose, use_intent, concurrency):
    tasks = []
    if (len(log_itemps_to_analyse) > 1):
        with ProcessPoolExecutor(max_workers=concurrency) as executor:
            eprint("launching %d analysis tasks" % len(log_itemps_to_analyse))
            counter = 0
            for logs in log_itemps_to_analyse:
                counter += 1
                eprint("%d  tasks submitted" % counter, end="\r")
                if (timestamp is None or timestamp == logs[0]):
                    tasks.append(executor.submit(check_conformance, logs, mgt_logs, verbose, use_intent))

            '''
            while True:
                done_tasks = len([t for t in tasks if t.done()])
                if done_tasks == len(tasks):
                    break;
                eprint("%10d/%10d processed" % (done_tasks, len(tasks)), end="\r")
                time.sleep(1)
            '''

            executor.shutdown(wait=True)

            sorted_resulsts = sorted([r.result() for r in tasks if r.result() is not None], key=lambda x: x[0])
            begining_of_time = int(sorted_resulsts[0][0])
            for i in range(0, len(sorted_resulsts)):
                sorted_resulsts[i].insert(1,(int(sorted_resulsts[i][0]) - begining_of_time) / 1000)

            for r in sorted_resulsts:
                print("\t".join([str(rr) for rr in r]))


    else:
        result = check_conformance(log_itemps_to_analyse[0], management_commands, verbose, use_intent)
        print("\t".join([str(rr) for rr in result]))



def init_path_cache(log):
    topo_logs_file,host_logs_file, flow_logs_file, intent_logs_file = log[1]

    hosts=set()

    g=nx.Graph()
    with open(topo_logs_file) as f:
        for line in f.readlines():
            src,dst=line[:-1].split("\t")
            g.add_edge(src[3:],dst[3:])
    with open(host_logs_file) as f:
        for line in f.readlines():
            ts,src,dst=line[:-1].split("\t")
            g.add_edge(src,dst[3:])
            hosts.add(src)

    for host1, host2 in [(aa, bb) for aa in hosts for bb in hosts if aa != bb]:
        cached_all_simple_path(g,host1,host2)




if __name__ == "__main__":

    check_connectivity = re.findall(MAC_PAIR_RE, args.check_connectivity)[0]
    check_src, check_dst = check_connectivity

    log_files = get_log_files(args.logs_dir)

    # need to scan all log files for timestamp

    if (args.timestamp is not None):
        args.all = True

    all_log_items = sorted(list(log_files.items()))
    if not args.intent:
        init_path_cache(all_log_items[0])

    if args.all:
        # scan everything
        if args.timestamp is None:
            log_itemps_to_analyse = all_log_items[:-3]
        else:
            log_itemps_to_analyse = [l for l in all_log_items if l[0]==args.timestamp]
    else:
        # scan a recent log (-3, to make sure we are not reading a file while Onos writes it)
        log_itemps_to_analyse = [all_log_items[-5]]

    mgt_logs = get_mgt_logs(args.management_commands)
    if(args.concurrency>1):
        run_conformance_multithread(args.timestamp, mgt_logs, args.verbose, args.intent, args.concurrency)
    else:
        run_confrmance_monothread(args.timestamp, mgt_logs, args.verbose, args.intent,
                                    args.concurrency)
