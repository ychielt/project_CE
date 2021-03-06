DETECT_VIRTUAL_MACHINE = ("vbox", "sandbox", "agent.pyw", "analyzer.py")
DETECT_VMWARE = ("Vmmouse.sys", "vm3dgl.dll", "vmdum.dll", "vm3dver.dll", "vmtray.dll", "VMToolsHook.dll",
                 "vmmousever.dll", "vmhgfs.dll", "vmGuestLib.dll", "VmGuestLibJava.dll", "vmhgfs.dll")
SNIFFER = ("sandbox", "wireshark", "procexec", "sniffer", "debugging", "superantispyware", "bopup observer")
file = open("autoruns_paths.txt", 'r')
autoruns_paths = file.readlines()
PATH_TO_APP_INFO = "CurrentVersion\\\\Uninstall"
EXECUTABLE_FILES_EXTENTIONS = "(\.exe|\.dll|\.bat|\.vbs|\.pyc|\.py|\.lnk|\.cmd)"
BACKGROUND_REG_PATH = "Control Panel\\\\Desktop"
OFFICE_FILE_EXTENTIONS = "(\.doc|\.docm|\.docx|\.pdf|\.ppt|\.ppts|\.pptx|\.xlm|\.xlsm)"
STARTUP_FOLDER_PATH = "AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup"
