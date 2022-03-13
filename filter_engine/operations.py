from procmon_parser.consts import FilesystemSetInformationOperation, ProcessOperation,\
    FilesystemOperation, RegistryOperation, \
    ProfilingOperation, NetworkOperation


class Process():
    Process_Create = ProcessOperation.Process_Create.name
    Load_Image = ProcessOperation.Load_Image.name


class FilSystem():
    SetBasicInformationFile = FilesystemSetInformationOperation.SetBasicInformationFile.name
    SetRenameInformationFile = FilesystemSetInformationOperation.SetRenameInformationFile.name
    CreateFile = FilesystemOperation.CreateFile.name
    WriteFile = FilesystemOperation.WriteFile.name


class Network():
    pass


class Registry():
    RegSetValue = RegistryOperation.RegSetValue.name
    RegSetInfoKey = RegistryOperation.RegSetInfoKey.name
    RegDeleteKey = RegistryOperation.RegDeleteKey.name
    RegDeleteValue = RegistryOperation.RegDeleteValue.name

process_operation = [ProcessOperation.Process_Create.name,
                     ProcessOperation.Load_Image.name]

registry_operation = [Registry.RegSetValue]
network_operation = []
file_system_operation = [FilSystem.SetBasicInformationFile,
                         FilSystem.SetRenameInformationFile]

# operations = ["RegDeleteValue",
#               "RegDeleteKey",
#               "RegSetValue",
#               "RegCreateKey",
#               "SetDispositionInformationFile",
#               "SetRenameInformationFile",
#               "WriteFile",
#               "CreateFile",
#               "CreatePipe",
#               "Process_Create",
#               "Load_Image"
#               "SetBasicInformationFile"
#               ]
# network = ["TCP Connect", "TCP Receive", "UDP Send", "UDP Receive"]
# CurrentControlSet\Services
# Software\Microsoft\Windows\CurrentVersion\Run
