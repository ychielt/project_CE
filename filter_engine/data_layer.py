DETECT_VIRTUAL_MACHINE = ("vm", "vbox", "sb", "sandbox")
SNIFFER = ("sandbox", "wireshark", "procmon", "procexec", "sniffer", "debugging", "superantispyware", "bopup observer")
file = open("autoruns_paths.txt",'r')
autoruns_paths = file.readlines()
PATH_TO_APP_INFO = "CurrentVersion\\\\Uninstall"
EXECUTABLE_FILES_EXTENTIONS = "(\.exe|\.dll|\.bat|\.vbs|\.pyc|\.py|\.js|\.lnk)"
BACKGROUND_REG_PATH = "Control Panel\\\\Desktop\\\\Wallpaper"
