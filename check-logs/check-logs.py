#!/usr/bin/env python3
import sys
import argparse
import time

from log_checker_lib import *
from log_checker_lib import check_dst, check_src
from log_checker_lib import MAC_PAIR_RE
from concurrent.futures import ProcessPoolExecutor

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
args = parser.parse_args()


def check_conformance(log_item, management_commands,verbose):
    timestamp, logs = log_item
    host_logs_file, flow_logs_file, intent_logs_file = logs
    host_logs = get_host_logs(host_logs_file)
    mgt_rules = get_mgt_logs(management_commands)
    flow_logs = get_flow_logs(flow_logs_file)
    timestamp = list(flow_logs.keys())[0]
    g = generate_flow_graph(flow_logs, timestamp)

    add_host_graph_nodes(g, host_logs, timestamp)

    macs = [(kk, vv) for kk, vv in host_logs.items() if kk == timestamp]
    if (len(macs) == 0):
        print("no log for this timestamp %s, skipping" % timestamp)
        return
    else:
        macs = macs[0][1]

    hosts_mac = sorted([h for h in macs.keys()])
    results = generate_connectivity_from_flow(g, hosts_mac)
    mgt_rules = get_mgt_rules_for_timestamp(timestamp, mgt_rules)
    all_success, fault_count = generate_conformance_results(results, mgt_rules,verbose)

    return display_conformance_results(all_success, fault_count, results, timestamp)


def run_conformance_multithread(timestamp, management_commands,verbose):
    tasks = []
    if (len(log_itemps_to_analyse) > 1):
        with ProcessPoolExecutor(max_workers=10) as executor:
            print("launching %d analysis tasks" % len(log_itemps_to_analyse))
            counter=0
            for logs in log_itemps_to_analyse:
                counter+=1
                print("%d  tasks submitted" % counter, end="\r")
                if (timestamp is None or timestamp == logs[0]):
                    tasks.append(executor.submit(check_conformance, logs, management_commands,verbose))

            while True:
                done_tasks = len([t for t in tasks if t.done()])
                if done_tasks == 0:
                    break;
                print("%10d/%10d processed" % (done_tasks, len(tasks)),end="\r")
                time.sleep(1)

            for r in sorted([r.result() for r in tasks if r.result() is not None], key=lambda x: x[0]):
                print(r)
    else:
        result = check_conformance(log_itemps_to_analyse[0], management_commands,verbose)
        print(result if result else "N/A")


if __name__ == "__main__":

    check_connectivity = re.findall(MAC_PAIR_RE, args.check_connectivity)[0]
    check_src, check_dst = check_connectivity

    log_files = get_log_files(args.logs_dir)

    # need to scan all log files for timestamp

    if (args.timestamp is not None):
        args.all = True

    all_log_items = sorted(list(log_files.items()))
    if args.all:
        # scan everything
        log_itemps_to_analyse = all_log_items
    else:
        # scan a recent log (-3, to make sure we are not reading a file while Onos writes it)
        log_itemps_to_analyse = [all_log_items[-3]]

    run_conformance_multithread(args.timestamp, args.management_commands,args.verbose)
