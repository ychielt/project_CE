import argparse

from filter_engine.GUI_util import *
from filter_engine.parser import get_summary

MAX_DISPLAYED_EVENTS = 10

 
def display_report(summary):
    root = Tk()
    root.geometry('1300x500+250+100')
    o = ScrollFrame(root)
    for s in summary.items():
        counter = 0
        title = ToggledFrame(o.frame, text=s[0]+f'  -  ({len(s[1])}  events)'+' '*550, relief="raised", borderwidth=0)
        title.pack(fill="x", expand=1, pady=2, padx=0, anchor="n")
        for ev in s[1]:
            if counter >= MAX_DISPLAYED_EVENTS:
                break
            counter += 1
            event = ToggledFrame(title.sub_frame, text=ev.process.process_name+',  '+str(ev.process.pid), relief="raised", borderwidth=0)
            event.pack(fill="x", expand=1, pady=0, anchor="n")
            Item('path', ev.path, event.sub_frame).pack(fill='x', side='top')   # path
            Item('details', str(ev.details), event.sub_frame).pack(fill='x', side='top') # details
            advanced = ToggledFrame(event.sub_frame, text='advanced', relief="raised", borderwidth=0)
            advanced.pack(fill="x", expand=1, pady=0, anchor="n")
            for item in ev.__dict__.items():
                if item[0] not in ['process', 'details', 'path', 'stacktrace', 'category']:
                    Item(item[0], item[1], advanced.sub_frame).pack(fill='x', side='top')
            process = ToggledFrame(event.sub_frame, text='process', relief="raised", borderwidth=0)
            process.pack(fill="x", expand=1, pady=0, anchor="n")
            for item in ev.process.__dict__.items():
                if item[0] == 'modules':
                    modules = ToggledFrame(process.sub_frame, text='modules', relief="raised", borderwidth=0)
                    modules.pack(fill="x", expand=1, pady=0, anchor="n")
                    for m in ev.process.modules:
                        Item('', m, modules.sub_frame).pack(fill='x', side='top')
                else:
                    Item(item[0], item[1], process.sub_frame).pack(fill='x', side='top')   # process attribute
    o.update()
    root.mainloop()


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
    display_report(summary)


if __name__ == '__main__':
    main()