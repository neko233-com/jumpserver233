"""A real Xorg/Tk desktop. The state file proves native target input delivery."""
import json
import os
import tkinter as tk

root = tk.Tk()
root.title('Jumpserver233 Native RDP QA')
root.geometry('1280x720+0+0')
root.configure(bg='#102b46')
root.attributes('-fullscreen', True)
clicks = 0
text = tk.StringVar()
status = tk.StringVar(value='Native Xorg desktop ready')

def save(*_):
    tmp = '/home/rdpqa/qa-state.tmp'
    with open(tmp, 'w') as stream:
        json.dump({'clicks': clicks, 'text': text.get(), 'display': os.environ.get('DISPLAY'), 'focus': root.focus_get() == entry}, stream)
    os.replace(tmp, '/home/rdpqa/qa-state.json')

def click():
    global clicks
    clicks += 1
    status.set('Native button clicks: ' + str(clicks))
    save()

def copy_text():
    root.clipboard_clear()
    root.clipboard_append(text.get())

def paste_text():
    try:
        text.set(root.clipboard_get())
    except tk.TclError:
        pass

tk.Label(root, text='Jumpserver233 · Native RDP QA', fg='white', bg='#102b46', font=('DejaVu Sans', 26)).place(x=40, y=30)
tk.Label(root, text='TLS verified · Real xrdp / Xorg / Tk', fg='#87dbb8', bg='#102b46', font=('DejaVu Sans', 16)).place(x=40, y=90)
tk.Button(root, text='Verify mouse', command=click, font=('DejaVu Sans', 16)).place(x=40, y=150, width=240, height=55)
tk.Button(root, text='Copy remote text', command=copy_text, font=('DejaVu Sans', 16)).place(x=750, y=150, width=280, height=55)
tk.Button(root, text='Paste remote text', command=paste_text, font=('DejaVu Sans', 16)).place(x=750, y=240, width=280, height=55)
entry = tk.Entry(root, textvariable=text, font=('DejaVu Sans', 18))
entry.place(x=40, y=240, width=600, height=48)
tk.Label(root, textvariable=status, fg='white', bg='#102b46', font=('DejaVu Sans', 16)).place(x=40, y=320)
for i, color in enumerate(['#e65757', '#41bf83', '#408ce4', '#ffce62']):
    tk.Frame(root, bg=color).place(x=40+i*150, y=400, width=130, height=110)
text.trace_add('write', save)
root.bind_all('<FocusIn>', lambda _: root.after_idle(save))
save()
root.mainloop()
