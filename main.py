import time

from filter_engine.operations import FilSystem
from procmon_parser import ProcmonLogsReader
from procmon_parser.consts import EventClass
from procmon_parser.logs import Event
from collections import defaultdict
from procmon_parser.stream_logs_detail_format import set_parse_details
import re

from textwrap import indent

f = open("cry1.PML", "rb")
pml_reader = ProcmonLogsReader(f)
print(len(pml_reader))

# operations = ["RegDeleteValue",
#               "RegDeleteKey",
#               "RegSetValue",
#               "RegCreateKey",
#               "SetDispositionInformationFile",
#               "SetRenameInformationFile",
#               "WriteFile",
#               "CreateFile",
#               "CreatePipe",
#               "Process Create",
#               "Load Image"
#               ]
# network = ["TCP Connect", "TCP Receive", "UDP Send", "UDP Receive"]
# d = {}
# pd = {}
# # for i in pml_reader:
# #     if i.process.pid not in d:
# #         d[i.process.pid] = 0
# #     else:
# #         d[i.process.pid] += 1
i: Event
for i in pml_reader:
    if i.process.pid == 3076 and i.operation == FilSystem.SetRenameInformationFile:
        print(i)
        print(i.details["Data"])

# print("p:")
# for i in p:
#     print(i)
# print("d:")
# for i in d.items():
#     print(str(i[0]))
# #    print(indent(str(i[1]), '    '))
