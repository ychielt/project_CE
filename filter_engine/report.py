import argparse
import json

from filter_engine.GUI_util import *
from filter_engine.parser import get_summary

MAX_DISPLAYED_EVENTS = 10


def orderDict_tostring(d):
    s = ''
    for item in d.items():
        s += f"{item[0]}: {item[1]}\n"
    return s[:-1]


def display_report(summary, pname, pid):
    root = Tk()
    root.title(f"report for process: '{pname}, {pid}'")
    root.geometry('1300x500+250+100')
    o = ScrollFrame(root)
    for s in summary.items():
        counter = 0
        title = ToggledFrame(o.frame, text=s[0].title+f'  -  ({len(s[1])}  events)'+' '*550, relief="raised", borderwidth=0)
        title.pack(fill="x", expand=1, pady=2, padx=0, anchor="n")
        for ev in s[1]:
            if counter >= MAX_DISPLAYED_EVENTS:
                break
            counter += 1
            event = ToggledFrame(title.sub_frame, text=ev.process.process_name+',  '+str(ev.process.pid), relief="raised", borderwidth=0)
            event.pack(fill="x", expand=1, pady=0, anchor="n")
            Item('path', ev.path, event.sub_frame).pack(fill='x', side='top')   # path
            Item('details', orderDict_tostring(ev.details), event.sub_frame).pack(fill='x', side='top') # details
            advanced = ToggledFrame(event.sub_frame, text='advanced', relief="raised", borderwidth=0)
            advanced.pack(fill="x", expand=1, pady=0, anchor="n")
            for item in ev.__dict__.items():
                if item[0] not in ['process', 'details', 'path', 'stacktrace', 'category']:
                    Item(item[0], item[1], advanced.sub_frame).pack(fill='x', side='top')
            process = ToggledFrame(event.sub_frame, text='process', relief="raised", borderwidth=0)
            process.pack(fill="x", expand=1, pady=0, anchor="n")
            for item in ev.process.__dict__.items():
                if item[0] == 'modules':
                    pass
                    # modules = ToggledFrame(process.sub_frame, text='modules', relief="raised", borderwidth=0)
                    # modules.pack(fill="x", expand=1, pady=0, anchor="n")
                    # for m in ev.process.modules:
                    #     Item('', str(m), modules.sub_frame).pack(fill='x', side='top')
                else:
                    Item(item[0], item[1], process.sub_frame).pack(fill='x', side='top')   # process attribute
    o.update()
    root.mainloop()


def report_to_json(summary):
    f = open("test.json", 'w')
    summary_j = {}
    for s in summary.items():
        title_name = s[0].title+f'  -  ({len(s[1])}  events)'
        for ev in s[1]:
            event_name = ev.process.process_name+',  '+str(ev.process.pid)
            summary_j[title_name] = {event_name:{}}
            summary_j[title_name][event_name]["path"] = ev.path
            summary_j[title_name][event_name]["details"] = orderDict_tostring(ev.details)
            summary_j[title_name][event_name]["advance"] = {}
            for item in ev.__dict__.items():
                if item[0] not in ['process', 'details', 'path', 'stacktrace', 'category']:
                    summary_j[title_name][event_name]["advance"][item[0]]= item[1]
            summary_j[title_name][event_name]["process"] = {}
            for item in ev.process.__dict__.items():
                if item[0] == 'modules':
                    summary_j[title_name][event_name]["process"]['modules'] = []
                    for m in ev.process.modules:
                        summary_j[title_name][event_name]["process"]['modules'].append(str(m))
                else:
                    summary_j[title_name][event_name]["process"][item[0]] = item[1]
    print(summary_j)
    f.write(json.dumps(summary_j))


def is_event_in(ev, l):
    for i in l:
        if ev.compare(i):
            return True
    return False


def unique_summary(summary: dict):
    for item in summary.items():
        tmp = []
        for ev in item[1]:
            ev.num = 1
            flag = True
            for i in tmp:
                if ev.process.pid == i.process.pid \
                        and ev.process.command_line == i.process.command_line \
                        and ev.path == i.path \
                        and orderDict_tostring(ev.details) == orderDict_tostring(i.details)\
                        and ev.result == i.result \
                        and ev.operation == i.operation:
                    i.num += 1
                    flag =False
                    break
            if flag:
                tmp.append(ev)
        summary[item[0]] = tmp
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pml_file")
    parser.add_argument("-pn", "--process_name", required=True)
    parser.add_argument("-pid", "--process_id", required=True)
    parser.add_argument("-tid", "--thread_id", default=0)
    parser.add_argument("-d", "--parse_rename_details", default=False)
    parser.add_argument("-p", "--partial_flow", default=False)
    args = parser.parse_args()
    summary = get_summary(args.pml_file,
                          args.process_name,
                          args.process_id,
                          args.thread_id,
                          args.parse_rename_details,
                          args.partial_flow)

    #summary = get_summary("dll_inject_py.PML", False)
    #report_to_json(summary)
    display_report(summary, args.process_name, args.process_id)


if __name__ == '__main__':
    main()


# LogfileFull.PML -pid 7896 -pn 1.exe
# dll_inject_py.PML -pid 19116 -pn python.exe