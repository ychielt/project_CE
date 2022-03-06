from procmon_parser import ProcmonLogsReader
from textwrap import indent

f = open("LogfileSublime.PML", "rb")
pml_reader = ProcmonLogsReader(f)
print(len(pml_reader))

operations = ["RegDeleteValue",
              "RegDeleteKey",
              "RegSetValue",
              "RegCreateKey",
              "SetDispositionInformationFile",
              "SetRenameInformationFile",
              "WriteFile",
              "CreateFile",
              "CreatePipe",
              "Process Create",
              "Load Image"
              ]
network = ["TCP Connect", "TCP Receive", "UDP Send", "UDP Receive"]
d = {}
pd = {}
# for i in pml_reader:
#     if i.process.pid not in d:
#         d[i.process.pid] = 0
#     else:
#         d[i.process.pid] += 1

for i in pml_reader:
    if i.process.parent_pid == 15828 or i.process.parent_pid in p:
        p.append(i.process.pid)
    if i.process.pid == 15828 or i.process.parent_pid in p:
        if i.operation not in d:
            d[i.operation] = [i.path]
        else:
            d[i.operation].append(i.path)

print("p:")
for i in p:
    print(i)
print("d:")
for i in d.items():
    print(str(i[0]))
#    print(indent(str(i[1]), '    '))
