import tkinter as tk
from tkinter import ttk, messagebox
import psutil
from datetime import datetime
import threading
import time
import os
import subprocess
from tkinter import simpledialog

class ProcessDetailsWindow:
    def __init__(self, parent, process_info):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Process Details - {process_info['name']} (PID: {process_info['pid']})")
        self.window.geometry("600x800")
        
        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)
        
        # Basic Info Tab
        self.basic_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.basic_frame, text='Basic Info')
        
        # Details Tab
        self.details_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.details_frame, text='Details')
        
        # Files & Connections Tab
        self.files_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.files_frame, text='Files & Connections')
        
        # Environment Tab
        self.env_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.env_frame, text='Environment')
        
        self.process = psutil.Process(process_info['pid'])
        self.populate_info()
    
    def populate_info(self):
        try:
            # Basic Info Tab
            basic_info = [
                ("Name", self.process.name()),
                ("PID", self.process.pid),
                ("Status", self.process.status()),
                ("Created", datetime.fromtimestamp(self.process.create_time()).strftime('%Y-%m-%d %H:%M:%S')),
                ("CPU %", f"{self.process.cpu_percent()}%"),
                ("Memory %", f"{self.process.memory_percent():.1f}%"),
                ("Nice", self.process.nice()),
                ("Threads", self.process.num_threads()),
            ]
            
            for i, (label, value) in enumerate(basic_info):
                ttk.Label(self.basic_frame, text=f"{label}:").grid(row=i, column=0, padx=5, pady=2, sticky='e')
                ttk.Label(self.basic_frame, text=str(value)).grid(row=i, column=1, padx=5, pady=2, sticky='w')
            
            # Add Priority Control
            ttk.Label(self.basic_frame, text="Priority:").grid(row=len(basic_info), column=0, padx=5, pady=10, sticky='e')
            priority_frame = ttk.Frame(self.basic_frame)
            priority_frame.grid(row=len(basic_info), column=1, padx=5, pady=10, sticky='w')
            
            ttk.Button(priority_frame, text="Increase", command=lambda: self.change_priority(1)).pack(side='left', padx=2)
            ttk.Button(priority_frame, text="Decrease", command=lambda: self.change_priority(-1)).pack(side='left', padx=2)
            
            # Details Tab
            details_text = tk.Text(self.details_frame, wrap=tk.WORD, height=20)
            details_text.pack(expand=True, fill='both', padx=5, pady=5)
            
            try:
                cmdline = " ".join(self.process.cmdline())
                parent = self.process.parent().name() if self.process.parent() else "None"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cmdline = "Access Denied"
                parent = "Access Denied"
            
            details_info = f"""Command Line:
{cmdline}

Parent Process:
{parent}

Threads: {self.process.num_threads()}
"""
            details_text.insert('1.0', details_info)
            details_text.config(state='disabled')
            
            # Files & Connections Tab
            files_text = tk.Text(self.files_frame, wrap=tk.WORD, height=20)
            files_text.pack(expand=True, fill='both', padx=5, pady=5)
            
            try:
                open_files = self.process.open_files()
                connections = self.process.connections()
                
                files_info = "Open Files:\n"
                for file in open_files:
                    files_info += f"{file.path}\n"
                
                files_info += "\nNetwork Connections:\n"
                for conn in connections:
                    files_info += f"Local: {conn.laddr}, Remote: {conn.raddr if conn.raddr else 'None'}, Status: {conn.status}\n"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                files_info = "Access Denied"
            
            files_text.insert('1.0', files_info)
            files_text.config(state='disabled')
            
            # Environment Tab
            env_text = tk.Text(self.env_frame, wrap=tk.WORD, height=20)
            env_text.pack(expand=True, fill='both', padx=5, pady=5)
            
            try:
                environ = self.process.environ()
                env_info = "\n".join(f"{k}={v}" for k, v in environ.items())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                env_info = "Access Denied"
            
            env_text.insert('1.0', env_info)
            env_text.config(state='disabled')
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot access process information: {str(e)}")
            self.window.destroy()
    
    def change_priority(self, delta):
        try:
            current_nice = self.process.nice()
            new_nice = max(-20, min(19, current_nice + delta))
            self.process.nice(new_nice)
            self.populate_info()  # Refresh the display
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot change process priority: {str(e)}")

class ProcessManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Manager")
        self.root.geometry("1000x800")
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="5")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create paned window for split view
        self.paned = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        self.paned.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Left frame for process tree
        self.tree_frame = ttk.Frame(self.paned)
        self.paned.add(self.tree_frame, weight=1)
        
        # Right frame for process list
        self.list_frame = ttk.Frame(self.paned)
        self.paned.add(self.list_frame, weight=2)
        
        # Search frame
        self.search_frame = ttk.Frame(self.main_frame)
        self.search_frame.grid(row=0, column=0, columnspan=2, pady=5, sticky=tk.W)
        
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.search_frame, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=0, padx=5)
        self.search_entry.bind('<KeyRelease>', self.filter_processes)
        
        ttk.Label(self.search_frame, text="Search:").grid(row=0, column=1, padx=5)
        
        # Create process tree
        self.process_tree = ttk.Treeview(self.tree_frame, columns=('PID', 'Name'), show='tree headings')
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('Name', text='Name')
        self.process_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create process list
        self.tree = ttk.Treeview(self.list_frame, 
                                columns=('PID', 'Name', 'CPU %', 'Memory %', 'Status', 'Threads'),
                                show='headings')
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure process list columns
        self.tree.heading('PID', text='PID')
        self.tree.heading('Name', text='Process Name')
        self.tree.heading('CPU %', text='CPU %')
        self.tree.heading('Memory %', text='Memory %')
        self.tree.heading('Status', text='Status')
        self.tree.heading('Threads', text='Threads')
        
        # Add scrollbars
        tree_scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        tree_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.process_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        list_scrollbar = ttk.Scrollbar(self.list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        list_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.tree.configure(yscrollcommand=list_scrollbar.set)
        
        # Buttons frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        ttk.Button(self.button_frame, text="Refresh", command=self.refresh_processes).grid(row=0, column=0, padx=5)
        ttk.Button(self.button_frame, text="End Process", command=self.end_process).grid(row=0, column=1, padx=5)
        ttk.Button(self.button_frame, text="Suspend", command=self.suspend_process).grid(row=0, column=2, padx=5)
        ttk.Button(self.button_frame, text="Resume", command=self.resume_process).grid(row=0, column=3, padx=5)
        ttk.Button(self.button_frame, text="Create Dump", command=self.create_dump).grid(row=0, column=4, padx=5)
        ttk.Button(self.button_frame, text="Details", command=self.show_details).grid(row=0, column=5, padx=5)
        
        # Process tracking
        self.process_cache = {}
        self.selected_pid = None
        self.first_visible = None
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        self.tree.bind('<Double-1>', lambda e: self.show_details())

        # Bind selection events
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        self.process_tree.bind('<<TreeviewSelect>>', self.on_tree_select)

        # Bind tracking events
        self.tree.bind('<<TreeviewOpen>>', lambda e: self.track_first_visible())
        self.tree.bind('<Motion>', lambda e: self.track_first_visible())
                
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)
        self.tree_frame.columnconfigure(0, weight=1)
        self.tree_frame.rowconfigure(0, weight=1)
        self.list_frame.columnconfigure(0, weight=1)
        self.list_frame.rowconfigure(0, weight=1)
        
        # Start update thread
        self.running = True
        self.update_thread = threading.Thread(target=self.auto_update)
        self.update_thread.daemon = True
        self.update_thread.start()
    
    def build_process_tree(self):
        """Build the process tree showing parent-child relationships"""
        self.process_tree.delete(*self.process_tree.get_children())
        processes = {}
        
        # First pass: collect all processes
        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                info = proc.info
                processes[info['pid']] = {
                    'pid': info['pid'],
                    'name': info['name'],
                    'ppid': info['ppid'],
                    'children': []
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Second pass: build parent-child relationships
        root_processes = []
        for pid, proc in processes.items():
            ppid = proc['ppid']
            if ppid in processes:
                processes[ppid]['children'].append(pid)
            else:
                root_processes.append(pid)
        
        # Insert processes into tree
        def insert_process(pid, parent=''):
            proc = processes[pid]
            item = self.process_tree.insert(parent, 'end', text=proc['name'],
                                          values=(pid, proc['name']))
            for child_pid in proc['children']:
                insert_process(child_pid, item)
        
        for pid in root_processes:
            insert_process(pid)
    
    def on_select(self, event):
        """Store the currently selected PID"""
        selection = self.tree.selection()
        if selection:
            self.selected_pid = self.tree.item(selection[0])['values'][0]
            
    def track_first_visible(self):
        """Track the first visible item to maintain scroll position"""
        try:
            children = self.tree.get_children()
            if children:
                region = self.tree.bbox(children[0])
                if region:
                    self.first_visible = self.tree.identify_row(region[1])
        except tk.TclError:
            pass
            
    def on_tree_select(self, event):
        """Handle selection in the process tree view"""
        selection = self.process_tree.selection()
        if selection:
            item = selection[0]
            pid = self.process_tree.item(item)['values'][0]
            # Select corresponding item in the process list
            for item in self.tree.get_children():
                if self.tree.item(item)['values'][0] == pid:
                    self.tree.selection_set(item)
                    self.tree.see(item)
                    break
    
    def show_details(self):
        """Show detailed process information window"""
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        values = self.tree.item(selected_item)['values']
        process_info = {'pid': values[0], 'name': values[1]}
        ProcessDetailsWindow(self.root, process_info)
    
    def suspend_process(self):
        """Suspend the selected process"""
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        pid = int(self.tree.item(selected_item)['values'][0])
        try:
            process = psutil.Process(pid)
            process.suspend()
            self.refresh_processes()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot suspend process: {str(e)}")
    
    def resume_process(self):
        """Resume the selected process"""
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        pid = int(self.tree.item(selected_item)['values'][0])
        try:
            process = psutil.Process(pid)
            process.resume()
            self.refresh_processes()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot resume process: {str(e)}")
    
    def create_dump(self):
        """Create a memory dump of the selected process"""
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        pid = int(self.tree.item(selected_item)['values'][0])
        
        try:
            # Create dumps directory if it doesn't exist
            if not os.path.exists('dumps'):
                os.makedirs('dumps')
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dump_path = f"dumps/process_{pid}_{timestamp}.dmp"
            
            if os.name == 'nt':  # Windows
                try:
                    subprocess.run(['procdump', '-ma', str(pid), dump_path], check=True)
                    messagebox.showinfo("Success", f"Process dump created at {dump_path}")
                except subprocess.CalledProcessError:
                    messagebox.showerror("Error", "Failed to create process dump. Make sure procdump is installed.")
                except FileNotFoundError:
                    messagebox.showerror("Error", "Procdump not found. Please install Sysinternals Procdump.")
            else:  # Linux
                try:
                    subprocess.run(['gcore', '-o', dump_path, str(pid)], check=True)
                    messagebox.showinfo("Success", f"Process dump created at {dump_path}")
                except subprocess.CalledProcessError:
                    messagebox.showerror("Error", "Failed to create process dump.")
                except FileNotFoundError:
                    messagebox.showerror("Error", "gcore not found. Please install gdb.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create process dump: {str(e)}")
    
    def get_processes(self):
        """Get list of running processes with detailed information"""
        processes = {}
        search_term = self.search_var.get().lower()
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                       'status', 'num_threads']):
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
                    'status': info['status'],
                    'num_threads': info['num_threads']
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
            process_info['status'],
            process_info['num_threads']
        )
        
        # Only update if values have changed
        if current_values != new_values:
            self.tree.item(item_id, values=new_values)
    
    def refresh_processes(self):
        """Refresh both the process list and process tree views"""
        # Update process list
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
                    process_info['status'],
                    process_info['num_threads']
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
        
        # Update process tree
        self.build_process_tree()
    
    def filter_processes(self, event=None):
        """Filter processes based on search term"""
        self.refresh_processes()
    
    def end_process(self):
        """Terminate the selected process"""
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
        """Automatically update process information"""
        while self.running:
            try:
                self.root.after(0, self.refresh_processes)
                time.sleep(2)
            except tk.TclError:
                break  # Exit if window is closed
    
    def on_closing(self):
        """Clean up when the window is closed"""
        self.running = False
        self.root.destroy()

def main():
    root = tk.Tk()
    app = ProcessManager(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()