import tkinter as tk
from tkinter import ttk, messagebox
import psutil
from datetime import datetime
import threading
import time
import os
import subprocess
from tkinter import simpledialog
import json
from PIL import Image, ImageTk
import pystray

from functools import partial
from collections import defaultdict

class ThemeManager:
    LIGHT_THEME = {
        'bg': '#ffffff',
        'fg': '#000000',
        'selected_bg': '#0078d7',
        'selected_fg': '#ffffff',
        'tree_bg': '#ffffff',
        'tree_fg': '#000000',
        'button_bg': '#e1e1e1',
        'frame_bg': '#f0f0f0'
    }
    
    DARK_THEME = {
        'bg': '#2d2d2d',
        'fg': '#ffffff',
        'selected_bg': '#0078d7',
        'selected_fg': '#ffffff',
        'tree_bg': '#1e1e1e',
        'tree_fg': '#ffffff',
        'button_bg': '#3d3d3d',
        'frame_bg': '#2d2d2d'
    }
    
    @classmethod
    def apply_theme(cls, root, is_dark=False):
        theme = cls.DARK_THEME if is_dark else cls.LIGHT_THEME
        style = ttk.Style()
        
        # Configure ttk styles
        style.configure('.',
            background=theme['bg'],
            foreground=theme['fg'],
            fieldbackground=theme['bg'])
        
        style.configure('Treeview',
            background=theme['tree_bg'],
            foreground=theme['tree_fg'],
            fieldbackground=theme['tree_bg'])
        
        style.configure('Treeview.Heading',
            background=theme['button_bg'],
            foreground=theme['fg'])
        
        style.map('Treeview',
            background=[('selected', theme['selected_bg'])],
            foreground=[('selected', theme['selected_fg'])])
        
        # Configure tk widgets
        root.configure(bg=theme['frame_bg'])
        
        return theme

class ProcessDetailsDialog:
    def __init__(self, parent, process_info):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Process Details - {process_info['name']}")
        self.window.geometry("500x600")
        
        # Wait for window to be visible
        self.window.wait_visibility()
        
        # Apply window manager hints
        self.window.attributes('-type', 'dialog')  # For X11 window managers
        self.window.focus_set()
        
        print("Debug - Creating ProcessDetailsDialog")
        
        # Create main container with padding
        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.process_info = process_info
        self.create_widgets()
    
    def create_widgets(self):
        print("Debug - Creating widgets")
        
        # Create content frame
        content_frame = ttk.Frame(self.main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create canvas and scrollbar
        canvas = tk.Canvas(content_frame)
        scrollbar = ttk.Scrollbar(content_frame, orient="vertical", command=canvas.yview)
        
        # Create frame for scrollable content
        self.scrollable_frame = ttk.Frame(canvas)
        
        # Configure scrolling
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        # Create window inside canvas
        canvas_frame = canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # Configure canvas to expand with window
        canvas.bind('<Configure>', lambda e: canvas.itemconfig(canvas_frame, width=e.width))
        
        # Pack canvas and scrollbar
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Add process details with better formatting
        details = [
            ("Process Name", self.process_info['name']),
            ("PID", str(self.process_info['pid'])),
            ("Status", self.process_info['status']),
            ("CPU Usage", f"{self.process_info['cpu_percent']:.1f}%"),
            ("Memory Usage", f"{self.process_info['memory_percent']:.1f}%"),
            ("User", self.process_info['username']),
            ("Priority", str(self.process_info['priority'])),
            ("Threads", str(self.process_info['num_threads'])),
            ("Start Time", self.process_info['start_time']),
            ("Path", self.process_info['path']),
            ("Command Line", self.process_info['cmdline'])
        ]
        
        # Create labels for each detail with improved styling
        for i, (label, value) in enumerate(details):
            # Container frame for each detail row
            row_frame = ttk.Frame(self.scrollable_frame)
            row_frame.pack(fill=tk.X, padx=5, pady=3)
            
            # Label with bold font
            label_widget = ttk.Label(row_frame, 
                                   text=f"{label}:", 
                                   width=15, 
                                   style='Bold.TLabel')
            label_widget.pack(side=tk.LEFT)
            
            # Value with word wrap
            value_widget = ttk.Label(row_frame, 
                                   text=str(value),
                                   wraplength=350)
            value_widget.pack(side=tk.LEFT, padx=(5, 0), fill=tk.X, expand=True)
        
        # Add close button
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        close_button = ttk.Button(button_frame, 
                                text="Close", 
                                command=self.window.destroy)
        close_button.pack(side=tk.RIGHT)
        
        # Bind mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        print("Debug - Dialog creation complete")
class ColumnCustomizer:
    DEFAULT_COLUMNS = {
        'PID': True,
        'Name': True,
        'CPU %': True,
        'Memory %': True,
        'Status': True,
        'Threads': True,
        'User': False,
        'Priority': False,
        'Path': False,
        'Command Line': False,
        'Start Time': False
    }
    
    def __init__(self, parent, current_columns):
        self.window = tk.Toplevel(parent)
        self.window.title("Customize Columns")
        self.window.geometry("300x400")
        
        self.columns = dict(self.DEFAULT_COLUMNS)
        self.columns.update(current_columns)
        
        self.create_widgets()
    
    def create_widgets(self):
        for i, (column, visible) in enumerate(self.columns.items()):
            var = tk.BooleanVar(value=visible)
            self.columns[column] = var
            ttk.Checkbutton(self.window, text=column, variable=var).grid(
                row=i, column=0, padx=5, pady=2, sticky='w')
        
        ttk.Button(self.window, text="Apply", command=self.apply_changes).grid(
            row=len(self.columns), column=0, pady=10)
    
    def apply_changes(self):
        self.result = {col: var.get() if isinstance(var, tk.BooleanVar) else var
                      for col, var in self.columns.items()}
        self.window.destroy()

class ProcessManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Manager")
        self.root.geometry("1200x800")
        
        # Initialize theme and settings
        self.is_dark_theme = False
        self.theme = ThemeManager.apply_theme(root, self.is_dark_theme)
        self.load_settings()
        
        # Initialize sorting
        self.sort_column = 'CPU %'
        self.sort_reverse = True
        self.sort_history = []
        
        self.setup_ui()
        self.setup_keyboard_shortcuts()
        self.setup_system_tray()
        
        # Start update thread
        self.running = True
        self.update_thread = threading.Thread(target=self.auto_update)
        self.update_thread.daemon = True
        self.update_thread.start()
    
    def setup_ui(self):
        # Menu Bar
        self.create_menu_bar()
        
        # Main Container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Toolbar
        self.create_toolbar()
        
        # Process View
        self.create_process_view()
        
        # Status Bar
        self.create_status_bar()
    
    def create_menu_bar(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Run New Task...", command=self.run_new_task)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # View Menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Customize Columns...", command=self.customize_columns)
        view_menu.add_checkbutton(label="Dark Theme", 
                                command=self.toggle_theme,
                                variable=tk.BooleanVar(value=self.is_dark_theme))
        
        # Group Menu
        self.group_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Group By", menu=self.group_menu)
        self.group_menu.add_command(label="None", command=lambda: self.group_processes(None))
        self.group_menu.add_command(label="Application Type", command=lambda: self.group_processes('type'))
        self.group_menu.add_command(label="User", command=lambda: self.group_processes('user'))
        self.group_menu.add_command(label="Priority", command=lambda: self.group_processes('priority'))
        self.group_menu.add_command(label="Resource Usage", command=lambda: self.group_processes('resource'))
    
    def create_toolbar(self):
        toolbar = ttk.Frame(self.main_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # Search
        self.search_var = tk.StringVar()
        ttk.Entry(toolbar, textvariable=self.search_var).pack(side=tk.LEFT, padx=5)
        self.search_var.trace('w', lambda *args: self.filter_processes())
        
        # Quick Actions
        ttk.Button(toolbar, text="End Task", command=self.end_process).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Suspend", command=self.suspend_process).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Resume", command=self.resume_process).pack(side=tk.LEFT, padx=2)
    
    def create_process_view(self):
        # Create Treeview
        self.tree = ttk.Treeview(self.main_frame, columns=list(self.visible_columns.keys()),
                                show='headings', selectmode='extended')
        
        # Configure columns and headings
        for col in self.visible_columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
            self.tree.column(col, width=100)
        
        # Scrollbars
        vsb = ttk.Scrollbar(self.main_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.main_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind events
        self.tree.bind('<Button-3>', self.show_context_menu)
        self.tree.bind('<Double-1>', lambda e: self.show_details())
    
    def show_details(self):
        """Show detailed information about the selected process"""
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        try:
            values = self.tree.item(selected_item[0])['values']
            pid = int(values[0])  # PID should be the first column
            
            # Get process info directly here
            process = psutil.Process(pid)
            
            # Add small delay to ensure CPU percent is calculated
            process.cpu_percent()
            time.sleep(0.1)  # Small delay for CPU measurement
            
            try:
                path = process.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                path = "Access Denied"
            
            try:
                cmdline = ' '.join(process.cmdline())
            except (psutil.AccessDenied, psutil.ZombieProcess):
                cmdline = "Access Denied"
            
            process_info = {
                'pid': pid,
                'name': process.name(),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'status': process.status(),
                'num_threads': process.num_threads(),
                'username': process.username(),
                'priority': process.nice(),
                'path': path,
                'cmdline': cmdline,
                'start_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            print("Debug - Process Info:", process_info)
            
            # Create dialog in the main thread
            self.root.after(0, lambda: ProcessDetailsDialog(self.root, process_info))
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot access process details: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def create_status_bar(self):
        self.status_bar = ttk.Label(self.main_frame, text="Ready", anchor=tk.W)
        self.status_bar.pack(fill=tk.X, padx=5, pady=2)
    
    def setup_keyboard_shortcuts(self):
        self.root.bind('<Control-e>', lambda e: self.end_process())
        self.root.bind('<Control-s>', lambda e: self.suspend_process())
        self.root.bind('<Control-r>', lambda e: self.resume_process())
        self.root.bind('<Control-g>', lambda e: self.show_details())
        self.root.bind('<F5>', lambda e: self.refresh_processes())
        self.root.bind('<Control-f>', lambda e: self.search_var.focus_set())
    
    def setup_system_tray(self):
        # Create system tray icon
        self.icon_image = Image.new('RGB', (64, 64), color='red')
        self.icon = pystray.Icon(
            "process_manager",
            self.icon_image,
            "Process Manager",
            menu=pystray.Menu(
                pystray.MenuItem("Show", self.show_window),
                pystray.MenuItem("Exit", self.on_closing)
            )
        )
    
    def minimize_to_tray(self):
        self.root.withdraw()
        self.icon.run()
    
    def show_window(self):
        self.root.deiconify()
        self.icon.stop()
    
    def show_context_menu(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="End Process", command=self.end_process)
        menu.add_command(label="Suspend Process", command=self.suspend_process)
        menu.add_command(label="Resume Process", command=self.resume_process)
        menu.add_separator()
        menu.add_command(label="Properties", command=self.show_details)
        menu.add_command(label="Open File Location", command=self.open_file_location)
        
        menu.post(event.x_root, event.y_root)
    
    def sort_by_column(self, column):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_reverse = False
            self.sort_column = column
        
        self.refresh_processes()
    
    def group_processes(self, group_by):
        if group_by is None:
            self.current_grouping = None
            self.refresh_processes()
            return
        
        processes = self.get_processes()
        groups = defaultdict(list)
        
        for proc in processes:
            if group_by == 'type':
                key = self.get_application_type(proc)
            elif group_by == 'user':
                key = proc.get('username', 'Unknown')
            elif group_by == 'priority':
                key = self.get_priority_group(proc)
            elif group_by == 'resource':
                key = self.get_resource_group(proc)
            else:
                key = 'Unknown'
            
            groups[key].append(proc)
        
        self.tree.delete(*self.tree.get_children())
        
        for group_name, group_processes in groups.items():
            group_id = self.tree.insert('', 'end', text=group_name, values=(group_name, '', '', '', '', ''))
            for proc in group_processes:
                self.insert_process(proc, parent=group_id)
    
    def get_application_type(self, proc):
        # Implement application type detection logic
        if proc['name'].endswith('.exe'):
            return 'Application'
        elif 'python' in proc['name'].lower():
            return 'Python Process'
        else:
            return 'System Process'
    
    def get_priority_group(self, proc):
        try:
            priority = psutil.Process(proc['pid']).nice()
            if priority < 0:
                return 'High Priority'
            elif priority > 0:
                return 'Low Priority'
            else:
                return 'Normal Priority'
        except:
            return 'Unknown Priority'
    
    def get_resource_group(self, proc):
        cpu = proc['cpu_percent']
        mem = proc['memory_percent']
        
        if cpu > 50 or mem > 50:
            return 'High Usage'
        elif cpu > 20 or mem > 20:
            return 'Medium Usage'
        else:
            return 'Low Usage'
    
    def load_settings(self):
        try:
            with open('process_manager_settings.json', 'r') as f:
                settings = json.load(f)
            self.visible_columns = settings.get('columns', ColumnCustomizer.DEFAULT_COLUMNS)
            self.is_dark_theme = settings.get('dark_theme', False)
        except:
            self.visible_columns = dict(ColumnCustomizer.DEFAULT_COLUMNS)
            self.is_dark_theme = False
    
    def save_settings(self):
        settings = {
            'columns': self.visible_columns,
            'dark_theme': self.is_dark_theme
        }
        with open('process_manager_settings.json', 'w') as f:
            json.dump(settings, f)  # Changed from json.dumps to json.dump

    
    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        self.theme = ThemeManager.apply_theme(self.root, self.is_dark_theme)
        self.save_settings()
    
    def customize_columns(self):
        customizer = ColumnCustomizer(self.root, self.visible_columns)
        self.root.wait_window(customizer.window)
        if hasattr(customizer, 'result'):
            self.visible_columns = customizer.result
            self.save_settings()
            self.refresh_processes()
    
    def run_new_task(self):
        program = simpledialog.askstring("Run New Task", "Enter the program name:")
        if program:
            try:
                subprocess.Popen(program)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to run program: {str(e)}")

    def get_processes(self):
        """Get list of running processes with detailed information"""
        processes = []
        search_term = self.search_var.get().lower()
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                       'status', 'num_threads', 'username', 'cmdline']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name']
                
                # Apply search filter
                if search_term and search_term not in str(pid).lower() and search_term not in name.lower():
                    continue
                
                # Get additional process information
                process = {
                    'pid': pid,
                    'name': name,
                    'cpu_percent': info['cpu_percent'] or 0.0,
                    'memory_percent': info['memory_percent'] or 0.0,
                    'status': info['status'],
                    'num_threads': info['num_threads'],
                    'username': info['username'],
                    'cmdline': ' '.join(info['cmdline']) if info['cmdline'] else '',
                    'priority': psutil.Process(pid).nice(),
                    'path': psutil.Process(pid).exe() if hasattr(psutil.Process(pid), 'exe') else 'N/A',
                    'start_time': datetime.fromtimestamp(psutil.Process(pid).create_time()).strftime('%Y-%m-%d %H:%M:%S')
                }
                
                processes.append(process)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Sort processes based on current sort criteria
        processes.sort(
            key=lambda x: (
                x[self.sort_column.lower().replace(' %', '_percent').replace(' ', '_')]
                if self.sort_column.lower().replace(' %', '_percent').replace(' ', '_') in x
                else ''),
            reverse=self.sort_reverse
        )
        
        return processes

    def refresh_processes(self):
        """Update the process list view with current information"""
        # Store selected items
        selected_items = self.tree.selection()
        selected_pids = [self.tree.item(item)['values'][0] for item in selected_items]
        
        # Clear tree
        self.tree.delete(*self.tree.get_children())
        
        # Get updated process list
        processes = self.get_processes()
        
        # Update tree
        for process in processes:
            values = []
            for column in self.visible_columns:
                if column == 'PID':
                    values.append(process['pid'])
                elif column == 'Name':
                    # Add CPU and Memory usage to the name
                    name_with_usage = f"{process['name']}"
                    values.append(name_with_usage)
                elif column == 'CPU %':
                    values.append(f"{process['cpu_percent']:.1f}")
                elif column == 'Memory %':
                    values.append(f"{process['memory_percent']:.1f}")
                elif column == 'Status':
                    values.append(process['status'])
                elif column == 'Threads':
                    values.append(process['num_threads'])
                elif column == 'User':
                    values.append(process['username'])
                elif column == 'Priority':
                    values.append(process['priority'])
                elif column == 'Path':
                    values.append(process['path'])
                elif column == 'Command Line':
                    values.append(process['cmdline'])
                elif column == 'Start Time':
                    values.append(process['start_time'])
            
            item = self.tree.insert('', 'end', values=values)
            
            # Restore selection if this was a selected process
            if process['pid'] in selected_pids:
                self.tree.selection_add(item)
        
        total_processes = len(processes)
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        self.status_bar.config(text=f"Processes: {total_processes} | CPU Usage: {cpu_usage:.1f}% | Memory Usage: {memory_usage:.1f}%")
        
    def end_process(self, event=None):
        """End selected process(es)"""
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        if len(selected_items) > 1:
            if not messagebox.askyesno("Confirm", f"Are you sure you want to end {len(selected_items)} processes?"):
                return
        
        for item in selected_items:
            try:
                pid = int(self.tree.item(item)['values'][0])
                process = psutil.Process(pid)
                process.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                messagebox.showerror("Error", f"Cannot terminate process {pid}: {str(e)}")
        
        self.refresh_processes()

    def suspend_process(self, event=None):
        """Suspend selected process(es)"""
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        for item in selected_items:
            try:
                pid = int(self.tree.item(item)['values'][0])
                process = psutil.Process(pid)
                process.suspend()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                messagebox.showerror("Error", f"Cannot suspend process {pid}: {str(e)}")
        
        self.refresh_processes()

    def resume_process(self, event=None):
        """Resume selected process(es)"""
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        for item in selected_items:
            try:
                pid = int(self.tree.item(item)['values'][0])
                process = psutil.Process(pid)
                process.resume()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                messagebox.showerror("Error", f"Cannot resume process {pid}: {str(e)}")
        
        self.refresh_processes()

    def open_file_location(self):
        """Open the file location of the selected process"""
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        try:
            pid = int(self.tree.item(selected_item[0])['values'][0])
            process = psutil.Process(pid)
            path = process.exe()
            if os.path.exists(path):
                if os.name == 'nt':  # Windows
                    os.system(f'explorer /select,"{path}"')
                else:  # Linux/Mac
                    os.system(f'xdg-open "{os.path.dirname(path)}"')
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot access process location: {str(e)}")

    def auto_update(self):
        """Background thread for automatic updates"""
        while self.running:
            try:
                self.root.after(0, self.refresh_processes)
                time.sleep(2)  # Update every 2 seconds
            except tk.TclError:
                break  # Exit if window is closed
    
    def on_closing(self):
        """Clean up when window is closed"""
        if messagebox.askokcancel("Quit", "Do you want to quit Process Manager?"):
            self.running = False
            self.save_settings()
            if hasattr(self, 'icon') and self.icon is not None:
                self.icon.stop()
            self.root.destroy()

def main():
    root = tk.Tk()
    app = ProcessManager(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()