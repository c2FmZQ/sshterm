import tkinter as tk
import json
import os

def log_event(msg):
    print(f"UI_EVENT: {msg}", flush=True)
    try:
        with open("/tmp/tkinter_ui.log", "a") as logf:
            logf.write(f"UI_EVENT: {msg}\n")
    except Exception:
        pass

root = tk.Tk()
root.title("Tkinter Test UI")
# Set a fixed size so coordinate clicking is deterministic
root.geometry("400x500+0+0")
root.resizable(False, False)

log_event("Tkinter UI started")

# 1. Entry widget (text input) at y=30
entry_var = tk.StringVar(value="")
entry_var.trace_add("write", lambda *args: log_event(f"entry_var changed to: {entry_var.get()}"))
entry = tk.Entry(root, textvariable=entry_var, font=("Courier", 12))
entry.place(x=50, y=30, width=300, height=30)
entry.focus_set()

# 2. Checkbutton widget at y=80
check_var = tk.BooleanVar(value=False)
check_var.trace_add("write", lambda *args: log_event(f"check_var changed to: {check_var.get()}"))
check = tk.Checkbutton(root, text="Enable Feature", variable=check_var, font=("Courier", 12))
check.place(x=50, y=80)

# 3. Radiobuttons group at y=130
radio_var = tk.IntVar(value=1)
radio_var.trace_add("write", lambda *args: log_event(f"radio_var changed to: {radio_var.get()}"))
radio1 = tk.Radiobutton(root, text="Option A", variable=radio_var, value=1, font=("Courier", 12))
radio1.place(x=50, y=130)
radio2 = tk.Radiobutton(root, text="Option B", variable=radio_var, value=2, font=("Courier", 12))
radio2.place(x=180, y=130)

# 4. Scale widget (slider) at y=180
scale_var = tk.DoubleVar(value=10.0)
scale_var.trace_add("write", lambda *args: log_event(f"scale_var changed to: {scale_var.get()}"))
scale = tk.Scale(root, from_=0, to=100, orient=tk.HORIZONTAL, variable=scale_var, font=("Courier", 10))
scale.place(x=50, y=180, width=300, height=45)

# 5. Listbox widget at y=240
listbox = tk.Listbox(root, selectmode=tk.SINGLE, font=("Courier", 12))
for item in ["Apple", "Banana", "Cherry", "Date"]:
    listbox.insert(tk.END, item)
listbox.place(x=50, y=240, width=300, height=80)

def on_listbox_select(event):
    selected_indices = listbox.curselection()
    selected_items = [listbox.get(i) for i in selected_indices]
    log_event(f"listbox selection changed to: {selected_items}")
listbox.bind("<<ListboxSelect>>", on_listbox_select)

def on_submit():
    log_event("on_submit called!")
    try:
        # Gather selections
        selected_indices = listbox.curselection()
        selected_items = [listbox.get(i) for i in selected_indices]
        
        state = {
            "text": entry_var.get(),
            "checked": check_var.get(),
            "radio": radio_var.get(),
            "scale": scale_var.get(),
            "listbox": selected_items,
            "success": True
        }
        log_event(f"Writing state: {state}")
        
        # Write the UI state to a shared temporary file
        with open("/tmp/tkinter_state.json", "w") as f:
            json.dump(state, f)
        log_event("State written successfully!")
    except Exception as e:
        log_event(f"Exception in on_submit: {e}")
    finally:
        root.destroy()

# 6. Button widget at y=360
submit_btn = tk.Button(root, text="Submit Form", command=on_submit, font=("Courier", 12))
submit_btn.place(x=130, y=360, width=140, height=40)

root.mainloop()

