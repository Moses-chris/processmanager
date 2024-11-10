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

class ProcessDetailsWindow:
    def __init__(self, parent, process_info):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Process Details - {process_info['name']} (PID: {process_info['pid']})")
        self.window.geometry("500x700")
        
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
        
        # Performance Tab
        self.perf_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.perf_frame, text='Performance')
        
        self.process = psutil.Process(process_info['pid'])
        
        # Add control buttons at the top
        self.create_control_buttons()
        
        # Start update timer
        self.running = True
        self.update_thread = threading.Thread(target=self.auto_update)
        self.update_thread.daemon = True
        self.update_thread.start()
        
        # Bind window close event
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.populate_info()
    
    def create_control_buttons(self):
        """Create process control buttons"""
        control_frame = ttk.LabelFrame(self.window, text="Process Control", padding="5")
        control_frame.pack(fill='x', padx=5, pady=5)
        
        # Create buttons grid
        buttons = [
            ("Suspend", self.suspend_process),
            ("Resume", self.resume_process),
            ("Stop", self.stop_process),
            ("Kill", self.kill_process),
            ("Debug", self.debug_process)
        ]
        
        # Priority control
        priority_frame = ttk.LabelFrame(control_frame, text="Priority Control")
        priority_frame.pack(fill='x', padx=5, pady=5)
        
        priorities = [
            ("Real Time", -20),
            ("High", -10),
            ("Above Normal", -5),
            ("Normal", 0),
            ("Below Normal", 5),
            ("Low", 10)
        ]
        
        for i, (label, nice) in enumerate(priorities):
            ttk.Button(
                priority_frame, 
                text=label,
                command=lambda n=nice: self.set_priority(n)
            ).pack(side='left', padx=2)
        
        # Process control buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        for text, command in buttons:
            ttk.Button(
                button_frame,
                text=text,
                command=command
            ).pack(side='left', padx=2)
    
    def populate_info(self):
        try:
            # Calculate uptime
            uptime = datetime.now() - datetime.fromtimestamp(self.process.create_time())
            uptime_str = str(uptime).split('.')[0]  # Remove microseconds
            
            # Basic Info Tab
            basic_info = [
                ("Name", self.process.name()),
                ("PID", self.process.pid),
                ("Status", self.process.status()),
                ("Created", datetime.fromtimestamp(self.process.create_time()).strftime('%Y-%m-%d %H:%M:%S')),
                ("Uptime", uptime_str),
                ("CPU %", f"{self.process.cpu_percent()}%"),
                ("Memory %", f"{self.process.memory_percent():.1f}%"),
                ("Memory Usage", f"{self.process.memory_info().rss / (1024*1024):.1f} MB"),
                ("Nice", self.process.nice()),
                ("Threads", self.process.num_threads()),
                ("Priority", self.get_priority_string(self.process.nice())),
                ("CPU Affinity", len(self.process.cpu_affinity())),
            ]
            
            # Clear previous widgets
            for widget in self.basic_frame.winfo_children():
                widget.destroy()
            
            for i, (label, value) in enumerate(basic_info):
                ttk.Label(self.basic_frame, text=f"{label}:", style='Bold.TLabel').grid(
                    row=i, column=0, padx=5, pady=2, sticky='e')
                ttk.Label(self.basic_frame, text=str(value)).grid(
                    row=i, column=1, padx=5, pady=2, sticky='w')
            
            # Performance Tab
            for widget in self.perf_frame.winfo_children():
                widget.destroy()
            
            # CPU and Memory usage over time
            cpu_usage = f"CPU Usage History:\n{'=' * int(self.process.cpu_percent())} {self.process.cpu_percent():.1f}%"
            mem_usage = f"Memory Usage History:\n{'=' * int(self.process.memory_percent())} {self.process.memory_percent():.1f}%"
            
            ttk.Label(self.perf_frame, text=cpu_usage).pack(pady=10)
            ttk.Label(self.perf_frame, text=mem_usage).pack(pady=10)
            
            # IO Counters
            try:
                io = self.process.io_counters()
                io_info = (
                    f"I/O Statistics:\n"
                    f"Read Bytes: {io.read_bytes / (1024*1024):.1f} MB\n"
                    f"Write Bytes: {io.write_bytes / (1024*1024):.1f} MB\n"
                    f"Read Count: {io.read_count}\n"
                    f"Write Count: {io.write_count}"
                )
                ttk.Label(self.perf_frame, text=io_info).pack(pady=10)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot access process information: {str(e)}")
            self.window.destroy()
    
    def get_priority_string(self, nice):
        """Convert nice value to priority string"""
        if nice <= -20:
            return "Real Time"
        elif nice <= -10:
            return "High"
        elif nice <= -5:
            return "Above Normal"
        elif nice <= 0:
            return "Normal"
        elif nice <= 5:
            return "Below Normal"
        else:
            return "Low"
    
    def set_priority(self, nice):
        """Set process priority"""
        try:
            self.process.nice(nice)
            self.populate_info()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot change process priority: {str(e)}")
    
    def suspend_process(self):
        """Suspend the process"""
        try:
            self.process.suspend()
            self.populate_info()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot suspend process: {str(e)}")
    
    def resume_process(self):
        """Resume the process"""
        try:
            self.process.resume()
            self.populate_info()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Cannot resume process: {str(e)}")
    
    def stop_process(self):
        """Stop the process gracefully"""
        if messagebox.askyesno("Confirm", "Are you sure you want to stop this process?"):
            try:
                self.process.terminate()
                self.window.destroy()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                messagebox.showerror("Error", f"Cannot stop process: {str(e)}")
    
    def kill_process(self):
        """Force kill the process"""
        if messagebox.askyesno("Confirm", "Are you sure you want to forcefully kill this process?"):
            try:
                self.process.kill()
                self.window.destroy()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                messagebox.showerror("Error", f"Cannot kill process: {str(e)}")
    
    def debug_process(self):
        """Attach debugger to the process"""
        try:
            if os.name == 'nt':  # Windows
                subprocess.Popen(['vsjitdebugger', '-p', str(self.process.pid)])
            else:  # Linux
                subprocess.Popen(['gdb', '-p', str(self.process.pid)])
        except FileNotFoundError:
            messagebox.showerror("Error", "Debugger not found. Please install appropriate debugging tools.")
        except Exception as e:
            messagebox.showerror("Error", f"Cannot attach debugger: {str(e)}")
    
    def auto_update(self):
        """Automatically update process information"""
        while self.running:
            try:
                self.window.after(0, self.populate_info)
                time.sleep(2)
            except tk.TclError:
                break
    
    def on_closing(self):
        """Clean up when window is closed"""
        self.running = False
        self.window.destroy()
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

        # Add right-click context menu
        self.context_menu = tk.Menu(root, tearoff=0)
        self.context_menu.add_command(label="End Process", command=self.end_process)
        self.context_menu.add_command(label="End Process Tree", command=self.end_process_tree)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Show Details", command=self.show_details)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="New Process", command=self.create_process)
        
        # Bind right-click event
        self.tree.bind('<Button-3>', self.show_context_menu)
    
    def setup_ui(self):
        # Menu Bar
        self.create_menu_bar()
        
        # Main Container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create button frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add buttons to button frame
        ttk.Button(self.button_frame, text="New Process", 
            command=self.create_process).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="End Tree", 
            command=self.end_process_tree).pack(side=tk.LEFT, padx=5)
        
        # Toolbar
        self.create_toolbar()
        
        # Process View
        self.create_process_view()
        
        # Status Bar
        self.create_status_bar()

    def load_settings(self):
        try:
            with open('process_manager_settings.json', 'r') as f:
                settings = json.load(f)
            self.visible_columns = settings.get('columns', ColumnCustomizer.DEFAULT_COLUMNS)
            self.is_dark_theme = settings.get('dark_theme', False)
            self.current_group_by = settings.get('group_by', None)
        except:
            self.visible_columns = dict(ColumnCustomizer.DEFAULT_COLUMNS)
            self.is_dark_theme = False
            self.current_group_by = None

    def save_settings(self):
        settings = {
            'columns': self.visible_columns,
            'dark_theme': self.is_dark_theme,
            'group_by': self.current_group_by
        }
        with open('process_manager_settings.json', 'w') as f:
            json.dump(settings, f)

    def get_application_type(self, proc):
        """Enhanced application type detection"""
        try:
            name = proc['name'].lower()
            cmdline = proc['cmdline'].lower()
            path = proc['path'].lower()

            # Common application categories
            browsers = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe', 'safari.exe']
            dev_tools = ['code.exe', 'idea64.exe', 'pycharm64.exe', 'sublime_text.exe', 'notepad++.exe']
            media_players = ['vlc.exe', 'wmplayer.exe', 'spotify.exe', 'musicbee.exe']
            office_apps = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']
            system_processes = ['svchost.exe', 'csrss.exe', 'lsass.exe', 'winlogon.exe', 'services.exe']
            
            # Categorize based on name and path
            if any(browser in name for browser in browsers):
                return 'Web Browsers'
            elif any(dev_tool in name for dev_tool in dev_tools):
                return 'Development Tools'
            elif any(media_player in name for media_player in media_players):
                return 'Media Players'
            elif any(office_app in name for office_app in office_apps):
                return 'Office Applications'
            elif any(sys_proc in name for sys_proc in system_processes):
                return 'System Processes'
            elif 'program files' in path:
                return 'Installed Applications'
            elif 'windows' in path:
                return 'Windows Components'
            elif name.endswith('.exe'):
                return 'Other Applications'
            elif 'python' in name or name.endswith('.py'):
                return 'Python Processes'
            else:
                return 'Background Processes'
        except:
            return 'Unknown'

    def group_processes(self, group_by):
        """Group processes with persistence"""
        self.current_group_by = group_by
        self.save_settings()
        self.refresh_processes()

    def refresh_processes(self):
        """Update the process list view maintaining grouping"""
        if not self.current_group_by:
            # Normal non-grouped view
            self._refresh_normal()
        else:
            self._refresh_grouped()

    def _refresh_grouped(self):
        """Refresh processes in grouped view"""
        processes = self.get_processes()
        groups = defaultdict(list)
        
        # Clear existing items
        self.tree.delete(*self.tree.get_children())
        
        # Group processes
        for proc in processes:
            if self.current_group_by == 'type':
                key = self.get_application_type(proc)
            elif self.current_group_by == 'user':
                key = proc.get('username', 'Unknown')
            elif self.current_group_by == 'priority':
                key = self.get_priority_group(proc)
            elif self.current_group_by == 'resource':
                key = self.get_resource_group(proc)
            else:
                key = 'Unknown'
            
            groups[key].append(proc)
        
        # Insert grouped processes
        for group_name, group_processes in sorted(groups.items()):
            # Create group header with summary information
            process_count = len(group_processes)
            total_cpu = sum(p['cpu_percent'] for p in group_processes)
            total_memory = sum(p['memory_percent'] for p in group_processes)
            
            group_values = [
                '',  # PID
                f"{group_name} ({process_count} processes)",  # Name
                f"{total_cpu:.1f}",  # CPU %
                f"{total_memory:.1f}",  # Memory %
                '',  # Status
                '',  # Threads
            ]
            
            # Add empty values for any additional columns
            group_values.extend([''] * (len(self.visible_columns) - len(group_values)))
            
            # Insert group header
            group_id = self.tree.insert('', 'end', values=group_values, tags=('group',))
            
            # Sort processes within group by CPU usage
            sorted_processes = sorted(group_processes, 
                                   key=lambda x: x['cpu_percent'], 
                                   reverse=True)
            
            # Insert processes in the group
            for proc in sorted_processes:
                self.insert_process(proc, parent=group_id)

    def _refresh_normal(self):
        """Refresh processes in normal view"""
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
                    values.append(process['name'])
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

    def show_context_menu(self, event):
        """Show context menu on right-click"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def show_details(self):
        """Show detailed process information window"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showinfo("Select Process", "Please select a process to view details.")
            return
        
        selected_item = selected_items[0]
        values = self.tree.item(selected_item)['values']
        
        try:
            # Verify process still exists and we have access
            process = psutil.Process(values[0])
            process.status()  # Quick check for process accessibility
            
            # Create style for bold labels if it doesn't exist
            style = ttk.Style()
            if 'Bold.TLabel' not in style.theme_names():
                style.configure('Bold.TLabel', font=('TkDefaultFont', 9, 'bold'))
            
            # Create process details window
            process_info = {
                'pid': values[0],
                'name': values[1],
                'status': values[4] if len(values) > 4 else 'Unknown',
            }
            
            # Check if a details window already exists for this process
            for window in self.root.winfo_children():
                if isinstance(window, tk.Toplevel):
                    try:
                        if window.process_info['pid'] == process_info['pid']:
                            window.lift()  # Bring existing window to front
                            window.focus_force()
                            return
                    except (AttributeError, KeyError):
                        continue
            
            # Create new details window
            details_window = ProcessDetailsWindow(self.root, process_info)
            
            # Position the window relative to the main window
            x = self.root.winfo_x() + 50
            y = self.root.winfo_y() + 50
            details_window.window.geometry(f"+{x}+{y}")
            
            # Store process info in the window for future reference
            details_window.window.process_info = process_info
            
        except psutil.NoSuchProcess:
            messagebox.showerror("Error", f"Process {values[0]} no longer exists.")
            self.refresh_processes()  # Refresh the process list
        except psutil.AccessDenied:
            messagebox.showerror("Error", 
                f"Access denied to process {values[0]}. Try running the application with administrator privileges.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open process details: {str(e)}")

    def create_process(self):
        """Create a new process"""
        command = simpledialog.askstring("Create Process", 
            "Enter the command to run:\n(e.g., 'notepad.exe' or 'python script.py')")
        
        if command:
            try:
                subprocess.Popen(command, shell=True)
                time.sleep(1)  # Give the process time to start
                self.refresh_processes()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create process: {str(e)}")

    def end_process_tree(self):
        """Terminate the selected process and all its children"""
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        pid = int(self.tree.item(selected_item)['values'][0])
        
        if messagebox.askyesno("Confirm", 
            "Are you sure you want to terminate this process and all its child processes?"):
            try:
                process = psutil.Process(pid)
                children = process.children(recursive=True)
                
                # First terminate children
                for child in children:
                    try:
                        child.terminate()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Then terminate parent
                process.terminate()
                
                # Wait for processes to terminate
                gone, alive = psutil.wait_procs(children + [process], timeout=3)
                
                # Force kill any remaining processes
                for p in alive:
                    try:
                        p.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                self.refresh_processes()
                
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                messagebox.showerror("Error", 
                    "Access denied. Cannot terminate some processes.")
            except Exception as e:
                messagebox.showerror("Error", f"Error terminating process tree: {str(e)}")



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

    def insert_process(self, process, parent=''):
        """Insert a process into the treeview"""
        values = []
        for column in self.visible_columns:
            if column == 'PID':
                values.append(process['pid'])
            elif column == 'Name':
                values.append(process['name'])
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
        
        return self.tree.insert(parent, 'end', values=values)
    
    # def group_processes(self, group_by):
    #     """Group processes based on specified criteria"""
    #     if group_by is None:
    #         self.refresh_processes()
    #         return
        
    #     processes = self.get_processes()
    #     groups = defaultdict(list)
        
    #     # Clear existing items
    #     self.tree.delete(*self.tree.get_children())
        
    #     # Group processes
    #     for proc in processes:
    #         if group_by == 'type':
    #             key = self.get_application_type(proc)
    #         elif group_by == 'user':
    #             key = proc.get('username', 'Unknown')
    #         elif group_by == 'priority':
    #             key = self.get_priority_group(proc)
    #         elif group_by == 'resource':
    #             key = self.get_resource_group(proc)
    #         else:
    #             key = 'Unknown'
            
    #         groups[key].append(proc)
        
    #     # Insert grouped processes
    #     for group_name, group_processes in sorted(groups.items()):
    #         # Create group header with summary information
    #         process_count = len(group_processes)
    #         total_cpu = sum(p['cpu_percent'] for p in group_processes)
    #         total_memory = sum(p['memory_percent'] for p in group_processes)
            
    #         group_values = [
    #             '',  # PID
    #             f"{group_name} ({process_count} processes)",  # Name
    #             f"{total_cpu:.1f}",  # CPU %
    #             f"{total_memory:.1f}",  # Memory %
    #             '',  # Status
    #             '',  # Threads
    #         ]
            
    #         # Add empty values for any additional columns
    #         group_values.extend([''] * (len(self.visible_columns) - len(group_values)))
            
    #         # Insert group header
    #         group_id = self.tree.insert('', 'end', values=group_values, tags=('group',))
            
    #         # Insert processes in the group
    #         for proc in sorted(group_processes, key=lambda x: x['cpu_percent'], reverse=True):
    #             self.insert_process(proc, parent=group_id)
        
    #     # Configure group header style
    #     style = ttk.Style()
    #     style.configure('Treeview', rowheight=25)
    #     self.tree.tag_configure('group', font=('TkDefaultFont', 9, 'bold'))
    # def get_application_type(self, proc):
    #     # Implement application type detection logic
    #     if proc['name'].endswith('.exe'):
    #         return 'Application'
    #     elif 'python' in proc['name'].lower():
    #         return 'Python Process'
    #     else:
    #         return 'System Process'
    
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