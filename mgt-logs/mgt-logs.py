#!/usr/bin/env python3

import argparse
import datetime
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.events import PatternMatchingEventHandler
import os
import sys
import sys


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def open_output_file(file_spec):
    if (file_spec == "-"):
        return open("/dev/stdout", "w")
    else:
        return open("/home/nherbaut/gt-logs.txt", "w+")


class MyFileSystemEventHandler(PatternMatchingEventHandler):

    def __init__(self, patterns, output_file):
        super(MyFileSystemEventHandler, self).__init__(patterns=patterns)
        self.output_file = output_file

    def on_modified(self, event):
        src_path = event.src_path
        self.dump_logs(src_path)

    def dump_logs(self, src_path):
        now = datetime.datetime.now().timestamp() * 1000
        with open_output_file(self.output_file) as fout:
            fout.write("%ld\tUPDATE\n" % now)
            with open(src_path, "r") as fin:
                for line in fin.readlines():
                    if not line.startswith("#"):
                        to_write = "%ld\t%s" % (now, line)
                        fout.write(to_write)


parser = argparse.ArgumentParser(description='Follow management')
parser.add_argument('-i', '--intput_file', type=str,
                    help='a file containing the mgt commands', default="/home/nherbaut/intent.txt")
parser.add_argument('-o', '--output_file', metavar='O', type=str,
                    help='a file containing the mgt commands', default="-")

args = parser.parse_args()

filename = os.path.basename(args.intput_file)
dirname = os.path.dirname(args.intput_file)

event_handler = MyFileSystemEventHandler([args.intput_file], output_file=args.output_file)

event_handler.dump_logs(args.intput_file)
observer = Observer()
observer.schedule(event_handler, dirname, recursive=False)
observer.start()

file_in = args.intput_file
while True:
    time.sleep(1)
