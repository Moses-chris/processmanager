import tkinter as tk
from tkinter import ttk
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
        
    def get_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return processes
    
    def refresh_processes(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Get and insert new processes
        processes = self.get_processes()
        search_term = self.search_var.get().lower()
        
        for proc in processes:
            if search_term in str(proc['pid']).lower() or search_term in proc['name'].lower():
                self.tree.insert('', tk.END, values=(
                    proc['pid'],
                    proc['name'],
                    f"{proc['cpu_percent']:.1f}",
                    f"{proc['memory_percent']:.1f}" if proc['memory_percent'] is not None else "N/A",
                    proc['status']
                ))
    
    def filter_processes(self, event=None):
        self.refresh_processes()
    
    def end_process(self):
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        pid = int(self.tree.item(selected_item)['values'][0])
        try:
            psutil.Process(pid).terminate()
            self.refresh_processes()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            tk.messagebox.showerror("Error", "Access denied. Cannot terminate this process.")
    
    def auto_update(self):
        while self.running:
            self.refresh_processes()
            time.sleep(2)
    
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