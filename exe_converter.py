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
    def exe_to_bat(exe_bytes):
        b64 = base64.b64encode(exe_bytes).decode('utf-8')
        chunks = [b64[i:i+70] for i in range(0, len(b64), 70)]
        
        echos = []
        for i, chunk in enumerate(chunks):
            if i == 0:
                echos.append(f"echo {chunk}>%tmp%\\x")
            else:
                echos.append(f"echo {chunk}>>%tmp%\\x")
        
        bat_template = r"""@echo off
{echos}
certutil -decode %tmp%\x %tmp%\x.exe >nul
start %tmp%\x.exe
del %tmp%\x
""".format(echos='\n'.join(echos))
        return bat_template.encode('utf-8')

    @staticmethod
    def exe_to_vbs(exe_bytes):
        b64 = base64.b64encode(exe_bytes).decode('utf-8')
        template = """
Set fs = CreateObject("Scripting.FileSystemObject")
Set tmp = fs.GetSpecialFolder(2)
Set x = fs.CreateTextFile(tmp & "\\x", True)
x.Write "{b64}"
x.Close

Set shell = CreateObject("WScript.Shell")
shell.Run "certutil -decode " & tmp & "\\x" & " " & tmp & "\\x.exe", 0, True
shell.Run tmp & "\\x.exe", 1, False
"""
        return template.format(b64=b64).encode('utf-8')

    @staticmethod
    def exe_to_js(exe_bytes):
        b64 = base64.b64encode(exe_bytes).decode('utf-8')
        template = """
var fs = new ActiveXObject("Scripting.FileSystemObject");
var tmp = fs.GetSpecialFolder(2);
var x = fs.CreateTextFile(tmp + "\\\\x", true);
x.Write("{b64}");
x.Close();

var shell = new ActiveXObject("WScript.Shell");
shell.Run('certutil -decode ' + tmp + '\\\\x ' + tmp + '\\\\x.exe', 0, true);
shell.Run(tmp + '\\\\x.exe', 1, false);
"""
        return template.format(b64=b64).encode('utf-8')

    @staticmethod
    def exe_to_ps1(exe_bytes):
        b64 = base64.b64encode(exe_bytes).decode('utf-8')
        template = """
$bytes = [System.Convert]::FromBase64String("{b64}")
$tmp = [System.IO.Path]::GetTempPath()
[System.IO.File]::WriteAllBytes("$tmp\\x.exe", $bytes)
Start-Process "$tmp\\x.exe"
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
            "bg": "#2c3e50",
            "fg": "#ecf0f1",
            "accent": "#3498db",
            "card": "#34495e",
            "success": "#2ecc71",
            "font": ("Segoe UI", 10),
            "title_font": ("Segoe UI", 18, "bold")
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
        
        # Format selection
        tk.Label(self.card_frame,
                text="SELECT OUTPUT FORMAT",
                font=(self.style["font"][0], self.style["font"][1], "bold"),
                bg=self.style["card"],
                fg=self.style["accent"]).pack(anchor=tk.W, pady=(0, 10))
        
        self.format_var = tk.StringVar(value="exe -> bat")
        formats = ["exe -> bat", "exe -> vbs", "exe -> js", "exe -> ps1"]
        
        format_frame = tk.Frame(self.card_frame, bg=self.style["card"])
        format_frame.pack(fill=tk.X, pady=(0, 20))
        
        if self.icons:
            tk.Label(format_frame,
                   image=self.icons["format"],
                   bg=self.style["card"]).pack(side=tk.LEFT, padx=(0, 5))
        
        format_menu = tk.OptionMenu(format_frame, self.format_var, *formats)
        format_menu.config(font=self.style["font"],
                         bg="white",
                         fg="#2c3e50",
                         activebackground=self.style["accent"],
                         width=18)
        format_menu.pack(side=tk.LEFT)
        
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
                output = ExeConverter.exe_to_bat(exe_bytes)
                ext = "bat"
            elif format_idx == "exe -> vbs":
                output = ExeConverter.exe_to_vbs(exe_bytes)
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