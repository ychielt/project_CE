from procmon_parser.consts import ProcessOperation, FilesystemOperation, ProfilingOperation, NetworkOperation


class Process():
    Process_Create = 'Process_Create'
    Load_Image = 'Load_Image'


class FilSystem():
    SetBasicInformationFile = 'SetBasicInformationFile'
    SetRenameInformationFile = "SetRenameInformationFile"


class Network():
    pass

class Registry():
    pass


process_operation = [ProcessOperation.Process_Create,
                        ProcessOperation.Load_Image]

registry_operation = []
network_operation = []
file_system_operation = ["SetRenameInformationFile",
                         "SetBasicInformationFile"]

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