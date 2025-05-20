import tkinter as tk
import tkinter.ttk as ttk
import tkinter.scrolledtext as scrolledtext

def create_widgets(self):
    # Tabbed Interface
    self.notebook = ttk.Notebook(self)
    self.notebook.place(x=10, y=35, width=500, height=550)
    
    # Prompt Tab
    self.prompt_frame = tk.Frame(self.notebook)
    self.notebook.add(self.prompt_frame, text="Prompt")
    tk.Label(self.prompt_frame, text="Natural Language Commands:").pack()
    self.prompt_box = scrolledtext.ScrolledText(self.prompt_frame, width=55, height=25, font=("Consolas", 11))
    self.prompt_box.pack()
    self.btn_generate = tk.Button(self.prompt_frame, text="Generate Assembly", command=self.generate_assembly)
    self.btn_generate.pack()
    
    # Assembly Tab
    self.asm_frame = tk.Frame(self.notebook)
    self.notebook.add(self.asm_frame, text="Assembly")
    tk.Label(self.asm_frame, text="ASM Code:").pack()
    self.code_box = scrolledtext.ScrolledText(self.asm_frame, width=55, height=25, font=("Consolas", 11))
    self.code_box.pack()
    
    # Output
    tk.Label(self, text="Output:").place(x=520, y=10)
    self.output_box = scrolledtext.ScrolledText(self, width=37, height=7, font=("Consolas", 11), state="disabled")
    self.output_box.place(x=520, y=35)
    # Registers
    tk.Label(self, text="Registers:").place(x=520, y=170)
    self.regs_box = scrolledtext.ScrolledText(self, width=37, height=7, font=("Consolas", 11), state="disabled")
    self.regs_box.place(x=520, y=195)
    # CPSR
    tk.Label(self, text="CPSR (Flags, Mode):").place(x=520, y=320)
    self.cpsr_box = scrolledtext.ScrolledText(self, width=37, height=3, font=("Consolas", 11), state="disabled")
    self.cpsr_box.place(x=520, y=345)
    # Memory
    tk.Label(self, text="Memory (first 128 bytes):").place(x=520, y=400)
    self.mem_box = scrolledtext.ScrolledText(self, width=37, height=10, font=("Consolas", 11), state="disabled")
    self.mem_box.place(x=520, y=425)
    # Buttons
    self.btn_load = tk.Button(self, text="Load", width=10, command=self.load_code)
    self.btn_load.place(x=10, y=600)
    self.btn_run = tk.Button(self, text="Run", width=10, command=self.run_program)
    self.btn_run.place(x=120, y=600)
    self.btn_step = tk.Button(self, text="Step", width=10, command=self.step_once)
    self.btn_step.place(x=230, y=600)
    self.btn_reset = tk.Button(self, text="Reset", width=10, command=self.reset_all)
    self.btn_reset.place(x=340, y=600)
