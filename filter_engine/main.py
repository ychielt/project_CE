import re

from filter_engine.operations import *
from procmon_parser import ProcmonLogsReader
from procmon_parser.consts import EventClass
from procmon_parser.logs import Event
from collections import defaultdict

PID = 17088
pids = {PID}
created_process = []
created_files = []
summary = defaultdict(list)


def is_relevant(i: Event):
    if i.process.parent_pid in pids:
        pids.add(i.process.pid)
        return True
    if i.process.pid in pids:
        return True
    return False


def network_filter(ev: Event):
    if ev.operation not in network_operation:
        return


def process_filter(ev: Event):
    if ev.operation not in process_operation:
        return
    created_process.append(ev)


def file_system_filter(ev: Event):
    if ev.operation not in file_system_operation:
        return
    if ev.operation == FilSystem.WriteFile:
        if re.search("(\.exe|\.dll|\.bat)", ev.path):
            summary[FilSystem.WriteFile].append(ev)
    elif ev.operation == FilSystem.CreateFile:
        if re.search("(\.bat)", ev.path):
            summary[FilSystem.CreateFile].append(ev)
            created_files.append(str(ev.path).split("/")[-1])
    elif ev.operation == FilSystem.SetRenameInformationFile:
        summary[FilSystem.SetRenameInformationFile].append(ev)
    elif ev.operation == FilSystem.SetBasicInformationFile:
        summary[FilSystem.SetBasicInformationFile].append(ev)


def registry_filter(ev: Event):
    if ev.operation not in registry_operation:
        return


def main():
    f = open("thread_create.PML", "rb")
    pml_reader = ProcmonLogsReader(f)
    print(len(pml_reader))

    filters = {EventClass.Process: process_filter,
               EventClass.Registry: registry_filter,
               EventClass.File_System: file_system_filter,
               EventClass.Network: network_filter}
    ev: Event
    for ev in pml_reader:
        print(ev.tid)
        print(ev.details)
        if not is_relevant(ev):
            continue
        if ev.event_class != EventClass.Profiling:
            filters[ev.event_class](ev)

    print(pids)
    print(created_process)
    print(created_files)

    for sum in summary.items():
        print(sum[0])
        for j in sum[1]:
            print(j)


if __name__ == '__main__':
    main()
