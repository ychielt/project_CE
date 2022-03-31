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


def regex_search(regex, msg):
    return re.search(regex, msg, re.IGNORECASE)


def is_relevant(i: Event):
    if i.process.pid in pids.keys() or i.tid in tids or i.tid in suspicious_threads:
        return True
    return False


def network_filter(ev: Event):
    if ev.operation not in network_operation:
        return
    #to do
    summary[Category("Open socket"), 0].append(ev)


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
            summary[Category("Inject DLL into another process through RemoteThread", 9)].append(ev)
        if not ev.path.lower().endswith(('dll', 'exe')):
            summary[Category("A file with an unusual extension was attempted to be loaded as a .DLL", 2)].append(ev)
    elif ev.operation == ProcessOp.Process_Create:
        summary[Category("Create new Process", 1)].append(ev)
        if "Command line" in ev.details:
            if regex_search("reg add|attrib|vssadmin|icacls|cmd\.exe|powershell\.exe", ev.details["Command line"]):
                summary[Category("Uses suspicious Command line tools or Windows utilities", 5)].append(ev)
            elif regex_search("schtasks", ev.details["Command line"]) and regex_search("/create", ev.details["Command line"]):
                if regex_search("regsvr32", ev.details["Command line"]):
                    summary[Category("Write Itself for autorun at Windows startup", 4)].append(ev)
                else:
                    summary[Category("One or more non-safelisted processes were created", 3)].append(ev)

        elif regex_search("vssadmin delete shadows", ev.process.command_line):
            summary[Category("Removes the Shadow Copy to avoid recovery of the system", 9)].append(ev)
        process_name = ev.path.split('\\')[-1]
        pids[ev.details["PID"]] = process_name
        created_process.append(ev)


def file_system_filter(ev: Event):
    if ev.operation not in file_system_operation:
        return
    if ev.operation == FilSystem.WriteFile:
        if regex_search(EXECUTABLE_FILES_EXTENTIONS, ev.path):
            summary[Category("Write to an executable file", 5)].append(ev)
            created_files.append(str(ev.path).split("/")[-1])
            if regex_search("\.lnk", ev.path):
                summary[Category("Create a shortcut to an executable file", 1)].append(ev)
        elif regex_search(STARTUP_FOLDER_PATH, ev.path):
            summary[Category("Write Itself for autorun at Windows startup", 4)].append(ev)
        elif ev.path.lower().endswith((".crt",".pem",".cer")):
            summary[Category("Attempts to create or modify system certificates", 7)].append(ev)
        elif regex_search(OFFICE_FILE_EXTENTIONS, ev.path):
            summary[Category("Creates office documents on filesystem ", 1)].append(ev)
    elif ev.operation == FilSystem.CreateFile:
        if ev.path.split("\\")[-1].lower().startswith(DETECT_VIRTUAL_MACHINE):
            summary[Category("Detect virtual machine through installed driver", 6)].append(ev)
        elif regex_search(STARTUP_FOLDER_PATH, ev.path):
            summary[Category("Engaging in startup folder", 3)].append(ev)
        elif "Command line" in ev.details and regex_search("vssadmin delete shadows", ev.details["Command line"]):
            summary[Category("Removes the Shadow Copy to avoid recovery of the system", 9)].append(ev)
        elif regex_search("\\\\avast|kaspersky|mcafee|antivirus", ev.path):
            summary[Category("Attempts to identify installed AV products by installation directory", 5)].append(ev)
    elif ev.operation == FilSystem.SetRenameInformationFile:
        if "FileName" in ev.details.keys():
            if regex_search(EXECUTABLE_FILES_EXTENTIONS+'$', ev.details["FileName"]):
                created_files.append(str(ev.path).split("/")[-1])
                summary[Category("Change file name extension to an executable file", 6)].append(ev)
            else:
                summary[Category("Change the file name", 1)].append(ev)
    elif ev.operation == FilSystem.SetBasicInformationFile:
        summary[Category("Change the file basic information", 2)].append(ev)


def registry_filter(ev: Event):
    if ev.operation not in registry_operation:
        return
    if ev.operation == Registry.RegOpenKey:
        if regex_search(PATH_TO_APP_INFO, ev.path):
            summary[Category("Query for potentially installed applications", 4)].append(ev)
        registry_name = str(ev.path).split("\\")[-1]
        if registry_name.lower().startswith(DETECT_VIRTUAL_MACHINE) or regex_search("(vmware|virtualvbox)", ev.path):
            summary[Category("Detect virtual machine through the presence of a registry key", 6)].append(ev)
        elif registry_name.lower().startswith(SNIFFER):
            summary[Category("Detect if any sniffer or debugger is installed", 6)].append(ev)
    elif ev.operation == Registry.RegSetValue or ev.operation == Registry.RegCreateKey:
        if regex_search("Windows\\\\CurrentVersion\\\\Internet Settings", ev.path):
            summary[Category("Sets or modifies Internet Explorer security zones", 3)].append(ev)
            if regex_search("\\\\Wpad", ev.path):
                summary[Category("Sets or modifies Wpad proxy auto configuration file for traffic interception", 3)].append(ev)
        elif regex_search("SystemCertificates\\\\AuthRoot\\\\Certificates", ev.path):
            summary[Category("Attempts to create or modify system certificates", 4)].append(ev)
        elif regex_search(BACKGROUND_REG_PATH, ev.path) and regex_search("Wallpaper", ev.path):
            summary[Category("Modify desktop wallpaper setting", 4)].append(ev)
        elif regex_search("CurrentVersion\\\\Windows\\\\LoadAppInit_DLLs", ev.path) and "Data" in ev.details and ev.details["Data"] != 0:
            summary[Category("Enable user32.dll to load all DLL's list from registry - High risk for DLL-injection", 7)].append(ev)
        elif regex_search("(CurrentVersion\\\\Windows\\\\AppInit_DLLs|Control\\\\Session Manager\\\\AppCertDLLs)", ev.path):
            summary[Category("Adding a DLL to be loaded persistently for most process in the system", 7)].append(ev)
        else:
            for path in autoruns_paths:
                if regex_search(path, ev.path):
                    summary[Category("Write Itself for autorun at Windows startup", 4)].append(ev)
                    break
    elif ev.operation == Registry.RegQueryValue or ev.operation == Registry.RegQueryKey:
        if regex_search(PATH_TO_APP_INFO, ev.path):
            summary[Category("Collects information about installed application", 4)].append(ev)
        elif regex_search("HARDWARE\\\\DESCRIPTION\\\\System\\\\CentralProcessor.*\\\\(Identifier|ProcessorNameString)", ev.path):
            summary[Category("Checks the CPU name from registry, possibly for anti-virtualization", 6)].append(ev)
    elif ev.operation == Registry.RegDeleteKey:
        summary[Category("Delete registry key", 3)].append(ev)
    elif ev.operation == Registry.RegDeleteValue:
        summary[Category("Delete registry value", 1)].append(ev)


def start_parsing(pml_reader, pb_win=None, pb=None):
    filters = {EventClass.Process: process_filter,
               EventClass.Registry: registry_filter,
               EventClass.File_System: file_system_filter,
               EventClass.Network: network_filter}
    ev: Event
    i = 0
    pb_step = 100/len(pml_reader)
    tmp =0
    for ev in pml_reader:
        if pb_win and pb:
            pb_win.update_idletasks()
            pb['value'] += pb_step
            tmp += pb_step
            text = tk.StringVar()
            text.set("Test")
        print(f'\r{str(i)}', end='')
        i += 1
        if not pids[PID] and ev.process.pid == PID:
            pids[PID] = ev.process.process_name
        if IS_PARTIAL:
            if ev.process.pid == PID:
                tids.add(ThreadInfo(ev.tid, ev.process.process_name))
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
    #start_parsing(pml_reader)
    start_action_with_progress_bar(start_parsing, pml_reader)
    return summary, pids[PID]



