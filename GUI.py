import tkinter as tk
import subprocess
import sys

def launch_domain_tool():
    root.destroy()
    subprocess.Popen([sys.executable, "domain_recon.py"])

def launch_url_tool():
    root.destroy()
    subprocess.Popen([sys.executable, "maliciousURLdetector.py"])

root = tk.Tk()
root.title("ReconX Toolkit")
root.geometry("400x300")
root.config(bg="black")

tk.Label(root, text="🛡️ ReconX Toolkit", font=("Segoe UI", 20, "bold"), fg="#82b1ff", bg="black").pack(pady=30)

tk.Button(root, text="🌐 Domain Recon Tool", font=("Segoe UI", 14, "bold"),
          bg="#3993c9", fg="white", width=25,
          activebackground="#3993c9", activeforeground="white",
          command=launch_domain_tool).pack(pady=10)

tk.Button(root, text="🔗 URL Scanner Tool", font=("Segoe UI", 14, "bold"),
          bg="#d69c3c", fg="black", width=25,
          activebackground="#d69c3c", activeforeground="black",
          command=launch_url_tool).pack(pady=10)

tk.Label(root, text="Choose a tool to begin analysis.", font=("Segoe UI", 11, "italic"),
         fg="#ffcc80", bg="black").pack(pady=(30, 0))

root.mainloop()
