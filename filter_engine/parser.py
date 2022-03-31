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
            summary[Category("Inject DLL into another process through RemoteThread")].append(ev)
        if not ev.path.endswith('dll'):
            summary[Category("A file with an unusual extension was attempted to be loaded as a .DLL")].append(ev)
    elif ev.operation == ProcessOp.Process_Create:
        summary[Category("Create new Process")].append(ev)
        if "Command line" in ev.details:
            if re.search("attrib|vssadmin|icacls|cmd\.exe|powershell\.exe", ev.details["Command line"]):
                summary["Uses suspicious Command line tools or Windows utilities"].append(ev)
            elif re.search("schtasks", ev.details["Command line"]) and re.search("/create", ev.details["Command line"]):
                if re.search("regsvr32", ev.details["Command line"]):
                    summary[Category("Write Itself for autorun at Windows startup")].append(ev)
                else:
                    summary[Category("One or more non-safelisted processes were created")].append(ev)

        elif re.search("vssadmin delete shadows", ev.process.command_line, re.IGNORECASE):
            summary[Category("Removes the Shadow Copy to avoid recovery of the system")].append(ev)
        process_name = ev.path.split('\\')[-1]
        pids[ev.details["PID"]] = process_name
        created_process.append(ev)


def file_system_filter(ev: Event):
    if ev.operation not in file_system_operation:
        return
    if ev.operation == FilSystem.WriteFile:
        if re.search(EXECUTABLE_FILES_EXTENTIONS, ev.path, re.IGNORECASE):
            summary[Category("Create an executable file")].append(ev)
            created_files.append(str(ev.path).split("/")[-1])
            if re.search("\.lnk", ev.path, re.IGNORECASE):
                summary[Category("Create a shortcut to an executable file")].append(ev)
        elif re.search(STARTUP_FOLDER_PATH, ev.path, re.IGNORECASE):
            summary[Category("Write Itself for autorun at Windows startup")].append(ev)
        elif ev.path.lower().endswith((".crt",".pem",".cer")):
            summary[Category("Attempts to create or modify system certificates")].append(ev)
        elif re.search(OFFICE_FILE_EXTENTIONS, ev.path, re.IGNORECASE):
            summary[Category("Creates office documents on filesystem ")].append(ev)
    elif ev.operation == FilSystem.CreateFile:
        if ev.path.split("\\")[-1].lower().startswith(DETECT_VIRTUAL_MACHINE):
            summary[Category("Detect virtual machine through installed driver")].append(ev)
        elif re.search(STARTUP_FOLDER_PATH, ev.path, re.IGNORECASE):
            summary[Category("Engaging in startup folder")].append(ev)
        elif "Command line" in ev.details and re.search("vssadmin delete shadows", ev.details["Command line"]):
            summary[Category("Uses suspicious command line tools or Windows utilities")].append(ev)
        elif re.search("\\\\avast|kaspersky|mcafee|antivirus", ev.path, re.IGNORECASE):
            summary[Category("Attempts to identify installed AV products by installation directory")].append(ev)
    elif ev.operation == FilSystem.SetRenameInformationFile:
        if "FileName" in ev.details.keys():
            if re.search(EXECUTABLE_FILES_EXTENTIONS, ev.details["FileName"], re.IGNORECASE):
                created_files.append(str(ev.path).split("/")[-1])
        summary[Category("Change the file name")].append(ev)
    elif ev.operation == FilSystem.SetBasicInformationFile:
        summary[Category("Change the file basic information ")].append(ev)


def registry_filter(ev: Event):
    if ev.operation not in registry_operation:
        return
    if ev.operation == Registry.RegOpenKey:
        if re.search(PATH_TO_APP_INFO, ev.path, re.IGNORECASE):
            summary[Category("Query for potentially installed applications")].append(ev)
        registry_name = str(ev.path).split("\\")[-1]
        if registry_name.lower().startswith(DETECT_VIRTUAL_MACHINE) or re.search("(vmware|virtualvbox)", ev.path, re.IGNORECASE):
            summary[Category("Detect virtual machine through the presence of a registry key")].append(ev)
        elif registry_name.lower().startswith(SNIFFER):
            summary[Category("Detect if any sniffer or debugger is installed")].append(ev)
    elif ev.operation == Registry.RegSetValue or ev.operation == Registry.RegCreateKey:
        if re.search("Windows\\\\CurrentVersion\\\\Internet Settings", ev.path, re.IGNORECASE):
            summary[Category("Sets or modifies Internet Explorer security zones")].append(ev)
        # if re.search("CurrentVersion\\\\Internet Settings\\\\Wpad", ev.path, re.IGNORECASE):
        #     summary["Sets or modifies Wpad proxy auto configuration file for traffic interception"].append(ev)
        elif re.search("SystemCertificates\\\\AuthRoot\\\\Certificates", ev.path, re.IGNORECASE):
            summary[Category("Attempts to create or modify system certificates")].append(ev)
        # elif re.search(BACKGROUND_REG_PATH, ev.path, re.IGNORECASE):
        #     summary[Category("Modify desktop wallpaper")].append(ev)
        elif re.search(BACKGROUND_REG_PATH, ev.path) and re.search("Wallpaper", ev.path, re.IGNORECASE):
            summary[Category("Modify desktop wallpaper setting")].append(ev)
        elif re.search("CurrentVersion\\\\Windows\\\\LoadAppInit_DLLs", ev.path, re.IGNORECASE) and "Data" in ev.details and ev.details["Data"] != 0:
            summary[Category("Enable user32.dll to load all DLL's list from registry - High risk for DLL-injection")].append(ev)
        elif re.search("(CurrentVersion\\\\Windows\\\\AppInit_DLLs|Control\\\\Session Manager\\\\AppCertDLLs)", ev.path, re.IGNORECASE):
            summary[Category("Adding a DLL to be loaded persistently for most process in the system")].append(ev)
        else:
            for path in autoruns_paths:
                if re.search(path, ev.path, re.IGNORECASE):
                    summary[Category("Write Itself for autorun at Windows startup")].append(ev)
                    break
    elif ev.operation == Registry.RegQueryValue or ev.operation == Registry.RegQueryKey:
        if re.search(PATH_TO_APP_INFO, ev.path, re.IGNORECASE):
            summary[Category("Collects information about installed application")].append(ev)
        elif re.search("HARDWARE\\\\DESCRIPTION\\\\System\\\\CentralProcessor", ev.path, re.IGNORECASE):
            summary["Checks the CPU name from registry, possibly for anti-virtualization"].append(ev)
    elif ev.operation == Registry.RegDeleteKey:
        summary[Category("Delete registry key")].append(ev)
    elif ev.operation == Registry.RegDeleteValue:
        summary[Category("Delete registry value")].append(ev)


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



