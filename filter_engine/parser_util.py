

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


class Category:
    def __init__(self, title, score):
        self.title = title
        self.score = score

    def __hash__(self):
        return hash(self.title)

    def __eq__(self, other):
        if type(self) == type(other):
            return self.title == other.title

    def __str__(self):
        return self.title

