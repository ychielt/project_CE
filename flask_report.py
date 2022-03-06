import sys

from flask import *

app = Flask(__name__)


from procmon_parser import ProcmonLogsReader
from textwrap import indent



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
f = open("LogfileSublime.PML", "rb")
pml_reader = ProcmonLogsReader(f)
print(len(pml_reader))
d = {}
p = []
for i in pml_reader:
    if i.process.parent_pid == 15828 or i.process.parent_pid in p:
        p.append(i.process.pid)
    if i.process.pid == 15828 or i.process.parent_pid in p:
        if i.operation in operations:
            if i.operation not in d:
                d[i.operation] = [i.path]
            else:
                if i.path not in d[i.operation]:
                    d[i.operation].append(i.path)


@app.route('/')
def get_report_page():

    return render_template('report.html', d=d)


if __name__ == '__main__':
    app.run(debug=True)