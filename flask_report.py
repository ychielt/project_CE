import sys

from flask import *

app = Flask(__name__)


from procmon_parser import ProcmonLogsReader
from textwrap import indent
from collections import defaultdict

operations = ["RegDeleteValue",
              "RegDeleteKey",
              "RegSetValue",
              "RegCreateKey",
              "SetDispositionInformationFile",
              "SetRenameInformationFile",
              "WriteFile",
              "CreateFile",
              "CreatePipe",
              "Process_Create",
              "Load_Image"
              "SetBasicInformationFile"
              ]
network = ["TCP Connect", "TCP Receive", "UDP Send", "UDP Receive"]
processes = []

f = open("LogfileFull.PML", "rb")
pml_reader = ProcmonLogsReader(f)
print(len(pml_reader))
d = defaultdict(list)
PID = 7896#8052
p = defaultdict(int)
p[PID] += 1
# count = 0
# for i in pml_reader:
#     count += 1
#     print('\r' + str(count), end='')
#     if i.process.parent_pid == PID or i.process.parent_pid in p:
#         p[i.process.pid] += 1
#     if i.process.pid not in p.keys():
#         continue
#     if i.operation in operations:
#         if i.path not in d[i.operation]:
#             d[i.operation].append(i.path)
#             if i.process.process_name not in processes:
#                 processes.append(i.process.process_name)
#     if i.operation == "Process_Create":
#         for pr in processes:
#             if pr in i.path:
#                 d["Process_Create2"].append(i.process.process_name + " , " + i.path)
# print(list(dict(p)))

@app.route('/')
def get_report_page():
    return render_template('report.html', d=d)


if __name__ == '__main__':
    count = 0
    for i in pml_reader:
        count += 1
        print('\r' + str(count), end='')
        if i.process.parent_pid == PID or i.process.parent_pid in p:
            p[i.process.pid] += 1
        if i.process.pid not in p.keys():
            continue
        if i.operation in operations:
            if i.path not in d[i.operation]:
                d[i.operation].append(i.process.process_name + " , " + i.path)
                if i.process.process_name not in processes:
                    processes.append(i.process.process_name)
        if i.operation == "Process_Create":
            for pr in processes:
                if pr in i.path:
                    d["Process_Create2"].append(i.process.process_name + " , " + i.path)
    print(list(dict(p)))
    print(processes)
    app.run(debug=True)