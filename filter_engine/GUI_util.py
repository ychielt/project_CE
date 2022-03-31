import tkinter as tk
from functools import partial
from tkinter import ttk
from tkinter import *
from tkinter.ttk import Progressbar


PROGRESS_BAR_LENGTH = 300


class Item(tk.Frame):
    def __init__(self, key, val, parent, text="", *args, **options):
        tk.Frame.__init__(self, parent, *args, **options)
        self.pack(fill='x', side='top')
        if key:
            ttk.Label(self, text=key, background='#bfbfbf', width=20).pack(side='left', fill='y')
        ttk.Label(self, text=val).pack(side='left')


class ToggledFrame(tk.Frame):

    def __init__(self, parent, text="", *args, **options):
        tk.Frame.__init__(self, parent, *args, **options)
        self.show = tk.IntVar()
        self.show.set(0)

        self.title_frame = ttk.Frame(self)
        self.title_frame.pack(fill='x', expand=1)

        #ttk.Label(self.title_frame, text=text).pack(side="right", fill='x', expand=1)

        self.toggle_button = ttk.Checkbutton(self.title_frame, text='+  '+text, command=self.toggle,
                                            variable=self.show, style='Toolbutton')
        self.toggle_button.pack(side="left", fill='x', expand=1)

        self.sub_frame = tk.Frame(self, relief="sunken", borderwidth=1)

    def toggle(self):
        if bool(self.show.get()):
            self.sub_frame.pack(fill="x", expand=1, padx=(8, 0))
            self.toggle_button.configure(text='-'+str(self.toggle_button.cget("text"))[1:])
        else:
            self.sub_frame.forget()
            self.toggle_button.configure(text='+'+str(self.toggle_button.cget("text"))[1:])


class AutoScrollbar(Scrollbar):
   # A scrollbar that hides itself if it's not needed.
   # Only works if you use the grid geometry manager!
    def set(self, lo, hi):
        if float(lo) <= 0.0 and float(hi) >= 1.0:
            # grid_remove is currently missing from Tkinter!
            self.tk.call("grid", "remove", self)
        else:
            self.grid()
        Scrollbar.set(self, lo, hi)

    def pack(self, **kw):
        raise TclError("cannot use pack with this widget")

    def place(self, **kw):
        raise TclError("cannot use place with this widget")


class ScrollFrame:
    def __init__(self, master):

        self.vscrollbar = AutoScrollbar(master)
        self.vscrollbar.grid(row=0, column=1, sticky=N+S)
        self.hscrollbar = AutoScrollbar(master, orient=HORIZONTAL)
        self.hscrollbar.grid(row=1, column=0, sticky=E+W)

        self.canvas = Canvas(master, yscrollcommand=self.vscrollbar.set,
                        xscrollcommand=self.hscrollbar.set)
        self.canvas.grid(row=0, column=0, sticky=N+S+E+W)

        self.vscrollbar.config(command=self.canvas.yview)
        self.hscrollbar.config(command=self.canvas.xview)

        # make the canvas expandable
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)

        # create frame inside canvas
        self.frame = Frame(self.canvas)
        self.frame.rowconfigure(0, weight=1)
        self.frame.columnconfigure(0, weight=1)
        self.frame.bind("<Configure>", self.reset_scrollregion)

    def reset_scrollregion(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def update(self):
        self.canvas.create_window(0, 0, anchor=NW, window=self.frame)
        self.frame.update_idletasks()
        self.canvas.config(scrollregion=self.canvas.bbox("all"))

        if self.frame.winfo_reqwidth() != self.canvas.winfo_width():
            # update the canvas's width to fit the inner frame
            self.canvas.config(width = self.frame.winfo_reqwidth())
        if self.frame.winfo_reqheight() != self.canvas.winfo_height():
            # update the canvas's width to fit the inner frame
            self.canvas.config(height = self.frame.winfo_reqheight())


def start_action_with_progress_bar(func, *args):
    pb_window = Tk()
    pb_window.title('parsing...')
    pb_window.geometry('400x250+500+200')

    progress_bar = Progressbar(pb_window, orient=HORIZONTAL, length=PROGRESS_BAR_LENGTH, mode='determinate')
    progress_bar.pack(expand=True)
    action = partial(func, *args, pb_window, progress_bar)
    Button(pb_window, text='Start', command=action, width=15).pack(side=LEFT, padx=(50, 0), pady=(0,15))
    Button(pb_window, text='close', command=pb_window.destroy, width=15).pack(side=RIGHT, padx=(0,50), pady=(0,15))
    pb_window.mainloop()