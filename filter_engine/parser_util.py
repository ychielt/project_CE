

class ThreadInfo:
    def __init__(self, tid, proc_name):
        self.tid = int(tid)
        self.proc_name = proc_name

    def __eq__(self, other):
        if isinstance(other, ThreadInfo):
            return other.tid == self.tid and other.proc_name == self.proc_name
        elif isinstance(other, int):
            return other == self.tid
        elif isinstance(other, str):
            return other == self.proc_name
        else:
            return False

    def __hash__(self):
        return self.tid