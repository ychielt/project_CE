import time

from filter_engine.data_layer import *
from filter_engine.operations import *
from filter_engine.GUI_util import *
from filter_engine.parser_util import *
from procmon_parser import ProcmonLogsReader
from procmon_parser.consts import EventClass
from procmon_parser.logs import Event
from collections import defaultdict
from procmon_parser.stream_logs_detail_format import set_parse_details
import re


IS_PARTIAL = False
PROC_NAME = "python.exe"#"1.exe"#"Explorer.EXE"#
PID = 19116#12040#7896#
pids = {}
tids = set()
#tids.add(8144)
root_proc_tid = 0
suspicious_threads = []
created_process = []
created_files = []
summary = defaultdict(list)


def is_relevant(i: Event):
    if i.process.pid in pids.keys() or i.tid in tids or i.tid in suspicious_threads:
        return True
    return False


def network_filter(ev: Event):
    if ev.operation not in network_operation:
        return
    summary[ev.operation].append(ev)


def process_filter(ev: Event):
    if ev.operation not in process_operation:
        return
    if ev.operation == ProcessOp.Thread_Create:
        if ev.tid in tids and ev.process.pid not in pids.keys():
            suspicious_threads.append(ev.details["Thread ID"])
        else:
            tids.add(ThreadInfo(ev.details["Thread ID"], ev.process.process_name))
    elif ev.operation == ProcessOp.Load_Image:
        if ev.process.process_name not in pids.values() and ev.tid in suspicious_threads:
            summary["dll_injection"].append(ev)
        if not ev.path.endswith('dll'):
            summary["A file with an unusual extension was attempted to be loaded as a .DLL"].append(ev)
    elif ev.operation == ProcessOp.Process_Create:
        if "Command line" in ev.details and re.search("attrib", ev.details["Command line"]):
            summary["Uses suspicious Windows utilities"].append(ev)
        elif re.search("(cmd\.exe|powershell\.exe)", ev.process.command_line.lower()):
            summary["Create a suspicious process"].append(ev)
        process_name =ev.path.split('\\')[-1]
        pids[ev.details["PID"]] = process_name
        created_process.append(ev)


def file_system_filter(ev: Event):
    if ev.operation not in file_system_operation:
        return
    if ev.operation == FilSystem.WriteFile:
        if re.search(EXECUTABLE_FILES_EXTENTIONS, ev.path.lower()):
            summary[FilSystem.WriteFile].append(ev)
            created_files.append(str(ev.path).split("/")[-1])
        if re.search("\.lnk", ev.path.lower()):
            summary["Create a shortcut to an executable file"].append(ev)
    elif ev.operation == FilSystem.CreateFile:
        if ev.path.split("\\")[-1].lower().startswith(DETECT_VIRTUAL_MACHINE):
            summary["Detect virtual machine through installed driver"].append(ev)
    elif ev.operation == FilSystem.SetRenameInformationFile:
        if "FileName" in ev.details.keys():
            if re.search(EXECUTABLE_FILES_EXTENTIONS, ev.details["FileName"].lower()):
                created_files.append(str(ev.path).split("/")[-1])
        summary[FilSystem.SetRenameInformationFile].append(ev)
    elif ev.operation == FilSystem.SetBasicInformationFile:
        summary[FilSystem.SetBasicInformationFile].append(ev)


def registry_filter(ev: Event):
    if ev.operation not in registry_operation:
        return
    if ev.operation == Registry.RegOpenKey:
        if re.search(PATH_TO_APP_INFO, ev.path):
            summary["Query for potentially installed applications"].append(ev)
        registry_name = str(ev.path).split("\\")[-1]
        if registry_name.lower().startswith(DETECT_VIRTUAL_MACHINE) or re.search("(vmware|virtualvbox)", str(ev.path).lower()):
            summary["Detect virtual machine through the presence of a registry key"].append(ev)
        elif registry_name.lower().startswith(SNIFFER):
            summary["Detect if any sniffer or debugger is installed"].append(ev)
    elif ev.operation == Registry.RegSetValue or ev.operation == Registry.RegCreateKey:
        for path in autoruns_paths:
            if re.search(path, ev.path):
                summary["Write Itself for autorun at Windows startup"].append(ev)
                break

        if re.search("CurrentVersion\\\\Internet Settings\\\\Wpad", ev.path):
            summary["Sets or modifies Wpad proxy auto configuration file for traffic interception"].append(ev)
        elif re.search(BACKGROUND_REG_PATH, ev.path):
            summary["Modify desktop wallpaper"].append(ev)
    elif ev.operation == Registry.RegQueryValue or ev.operation == Registry.RegQueryKey:
        if re.search(PATH_TO_APP_INFO, ev.path):
            summary["Collects information about installed application"].append(ev)
    elif ev.operation == Registry.RegDeleteKey:
        summary[Registry.RegDeleteKey].append(ev)
    elif ev.operation == Registry.RegDeleteValue:
        summary[Registry.RegDeleteValue].append(ev)
    elif ev.operation == Registry.RegSetInfoKey:
        # to do ???
        pass


def start_parsing(pml_reader, pb_win=None, pb=None):
    filters = {EventClass.Process: process_filter,
               EventClass.Registry: registry_filter,
               EventClass.File_System: file_system_filter,
               EventClass.Network: network_filter}
    ev: Event
    i = 0
    pb_step = PROGRESS_BAR_LENGTH/len(pml_reader)
    for ev in pml_reader:
        if i == 2434137:
            print()
        if pb_win and pb:
            pb_win.update_idletasks()
            pb['value'] += pb_step
            text = tk.StringVar()
            text.set("Test")
        print('\r' + str(i), end='')
        i += 1
        if IS_PARTIAL:
            if ev.process.pid == PID:
                tids.add(ThreadInfo(ev.details["Thread ID"], ev.process.process_name))
        if not tids:
            if ev.operation == ProcessOp.Thread_Create and ev.process.pid == PID:
                tids.add(ThreadInfo(ev.details["Thread ID"], ev.process.process_name))
            continue
        if not is_relevant(ev):
            continue
        if ev.event_class != EventClass.Profiling:
            filters[ev.event_class](ev)
    if pb_win and pb:
        pb_win.destroy()


def get_summary(pml_file, proc_name, pid=0, tid=0, parse_rename_details=False, is_partial=False):
    global PROC_NAME, PID, IS_PARTIAL
    PID = int(pid)
    IS_PARTIAL = is_partial
    PROC_NAME = proc_name
    if tid != 0:
        tids.add(tid)
    pids[PID] = PROC_NAME
    set_parse_details(parse_rename_details)

    f = open(pml_file, "rb")
    pml_reader = ProcmonLogsReader(f)
    print(len(pml_reader))
    start_parsing(pml_reader)
    #start_action_with_progress_bar(start_parsing, pml_reader)
    return summary
    # print()
    # print(pids)
    # print(created_process)
    # print(created_files)
    # for sum in summary.items():
    #     print(sum[0])
    #     for j in sum[1]:
    #         print(j)
    # with open("summary.json",'w') as f:
    #     f.write(json.dumps(summary))


