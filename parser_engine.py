from procmon_parser import ProcmonLogsReader, logs, consts
from textwrap import indent
from collections import defaultdict

operations = ["RegDeleteValue",
              "RegDeleteKey",
              "RegSetValue",
              "RegCreateKey",
              "SetDispositionInformationFile",
              "SetRenameInformationFile",
              "SetBasicInformationFile"
              "WriteFile",
              "CreateFile",
              "CreatePipe",
              "Process_Create",
              "Load_Image"
              ]
network = ["TCP Connect", "TCP Receive", "UDP Send", "UDP Receive"]
processes = []

f = open("LogfileFull.PML", "rb")
pml_reader = ProcmonLogsReader(f)
print(len(pml_reader))
d = defaultdict(list)
PID = 8052
p = defaultdict(int)
p[PID] += 1
i: logs.Event
dddd= {}
for i in pml_reader:
    if i.process.parent_pid == PID or i.process.parent_pid in p:
        p[i.process.pid] += 1
    if i.process.pid not in p:
        continue
    if i.operation in operations:
        if i.operation not in d:
            if i.path not in d[i.operation]:
                d[i.operation].append(i.path)
                if i.process.process_name not in processes:
                    processes.append(i.process.process_name)
    if i.operation == "Process_Create":
        for p in processes:
            if p in i.path:
                d["Process_Create2"].append(i.process.process_name + " , " + i.path)
print(list(dddd))