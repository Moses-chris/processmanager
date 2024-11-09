import tkinter as tk
from tkinter import ttk, messagebox
import psutil
from datetime import datetime
import threading
import time

class ProcessManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Manager")
        self.root.geometry("800x600")
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="5")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Search frame
        self.search_frame = ttk.Frame(self.main_frame)
        self.search_frame.grid(row=0, column=0, columnspan=2, pady=5, sticky=tk.W)
        
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.search_frame, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=0, padx=5)
        self.search_entry.bind('<KeyRelease>', self.filter_processes)
        
        ttk.Label(self.search_frame, text="Search:").grid(row=0, column=1, padx=5)
        
        # Create treeview
        self.tree = ttk.Treeview(self.main_frame, columns=('PID', 'Name', 'CPU %', 'Memory %', 'Status'), show='headings')
        self.tree.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure treeview columns
        self.tree.heading('PID', text='PID')
        self.tree.heading('Name', text='Process Name')
        self.tree.heading('CPU %', text='CPU %')
        self.tree.heading('Memory %', text='Memory %')
        self.tree.heading('Status', text='Status')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=1, column=2, sticky=(tk.N, tk.S))
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Buttons frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        ttk.Button(self.button_frame, text="Refresh", command=self.refresh_processes).grid(row=0, column=0, padx=5)
        ttk.Button(self.button_frame, text="End Process", command=self.end_process).grid(row=0, column=1, padx=5)
        
        # Process tracking
        self.process_cache = {}
        self.selected_pid = None
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        
        # Start update thread
        self.running = True
        self.update_thread = threading.Thread(target=self.auto_update)
        self.update_thread.daemon = True
        self.update_thread.start()
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)
        
        # Track the first visible item for scroll position
        self.first_visible = None
        self.tree.bind('<<TreeviewOpen>>', self.update_first_visible)
        self.tree.bind('<Motion>', self.update_first_visible)
    
    def update_first_visible(self, event=None):
        """Track the first visible item to maintain scroll position"""
        region = self.tree.bbox(self.tree.get_children()[0])
        if region:
            self.first_visible = self.tree.identify_row(region[1])

    def on_select(self, event):
        """Store the currently selected PID"""
        selection = self.tree.selection()
        if selection:
            self.selected_pid = self.tree.item(selection[0])['values'][0]
    
    def get_processes(self):
        processes = {}
        search_term = self.search_var.get().lower()
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name']
                
                if search_term and search_term not in str(pid).lower() and search_term not in name.lower():
                    continue
                    
                processes[pid] = {
                    'pid': pid,
                    'name': name,
                    'cpu_percent': info['cpu_percent'],
                    'memory_percent': info['memory_percent'],
                    'status': info['status']
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return processes
    
    def update_tree_item(self, item_id, process_info):
        """Update a single tree item with new process information"""
        current_values = self.tree.item(item_id)['values']
        new_values = (
            process_info['pid'],
            process_info['name'],
            f"{process_info['cpu_percent']:.1f}",
            f"{process_info['memory_percent']:.1f}" if process_info['memory_percent'] is not None else "N/A",
            process_info['status']
        )
        
        # Only update if values have changed
        if current_values != new_values:
            self.tree.item(item_id, values=new_values)
    
    def refresh_processes(self):
        new_processes = self.get_processes()
        existing_items = {self.tree.item(item_id)['values'][0]: item_id 
                         for item_id in self.tree.get_children()}
        
        # Update existing items and track which ones are still present
        updated_pids = set()
        for pid, process_info in new_processes.items():
            if pid in existing_items:
                self.update_tree_item(existing_items[pid], process_info)
                updated_pids.add(pid)
            else:
                # Add new process
                self.tree.insert('', tk.END, values=(
                    process_info['pid'],
                    process_info['name'],
                    f"{process_info['cpu_percent']:.1f}",
                    f"{process_info['memory_percent']:.1f}" if process_info['memory_percent'] is not None else "N/A",
                    process_info['status']
                ))
        
        # Remove items that no longer exist
        for pid, item_id in existing_items.items():
            if pid not in updated_pids:
                self.tree.delete(item_id)
        
        # Restore selection if possible
        if self.selected_pid:
            for item_id in self.tree.get_children():
                if self.tree.item(item_id)['values'][0] == self.selected_pid:
                    self.tree.selection_set(item_id)
                    break
        
        # Restore scroll position
        if self.first_visible:
            try:
                self.tree.see(self.first_visible)
            except:
                pass
    
    def filter_processes(self, event=None):
        # Store current selection and scroll position
        self.refresh_processes()
    
    def end_process(self):
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        pid = int(self.tree.item(selected_item)['values'][0])
        try:
            psutil.Process(pid).terminate()
            self.selected_pid = None  # Clear selection after termination
            self.refresh_processes()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            messagebox.showerror("Error", "Access denied. Cannot terminate this process.")
    
    def auto_update(self):
        while self.running:
            try:
                self.root.after(0, self.refresh_processes)
                time.sleep(2)
            except tk.TclError:
                break  # Exit if window is closed
    
    def on_closing(self):
        self.running = False
        self.root.destroy()

def main():
    root = tk.Tk()
    app = ProcessManager(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()