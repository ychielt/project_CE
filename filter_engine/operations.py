from procmon_parser.consts import FilesystemSetInformationOperation, ProcessOperation,\
    FilesystemOperation, RegistryOperation, \
    NetworkOperation


class ProcessOp:
    Process_Create = ProcessOperation.Process_Create.name
    Load_Image = ProcessOperation.Load_Image.name
    Thread_Create = ProcessOperation.Thread_Create.name


class FilSystem:
    SetBasicInformationFile = FilesystemSetInformationOperation.SetBasicInformationFile.name
    SetRenameInformationFile = FilesystemSetInformationOperation.SetRenameInformationFile.name
    CreateFile = FilesystemOperation.CreateFile.name
    WriteFile = FilesystemOperation.WriteFile.name


class Network:
    Connect = NetworkOperation.Connect.name
    Disconnect = NetworkOperation.Disconnect.name
    Reconnect = NetworkOperation.Reconnect.name
    Accept = NetworkOperation.Accept.name
    Send = NetworkOperation.Send.name
    Receive = NetworkOperation.Receive.name
    TCPCopy = NetworkOperation.TCPCopy.name


class Registry:
    RegSetValue = RegistryOperation.RegSetValue.name
    RegSetInfoKey = RegistryOperation.RegSetInfoKey.name
    RegDeleteKey = RegistryOperation.RegDeleteKey.name
    RegDeleteValue = RegistryOperation.RegDeleteValue.name
    RegOpenKey = RegistryOperation.RegOpenKey.name
    RegQueryValue = RegistryOperation.RegQueryValue.name
    RegQueryKey = RegistryOperation.RegQueryKey.name
    RegCreateKey = RegistryOperation.RegCreateKey


process_operation = [item[1] for item in ProcessOp.__dict__.items() if isinstance(item[1], str)]
registry_operation = [item[1] for item in Registry.__dict__.items() if isinstance(item[1], str)]
network_operation = [item[1] for item in Network.__dict__.items() if isinstance(item[1], str)]
file_system_operation = [item[1] for item in FilSystem.__dict__.items() if isinstance(item[1], str)]
