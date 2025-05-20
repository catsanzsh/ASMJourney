import tkinter as tk
import tkinter.ttk as ttk
import tkinter.scrolledtext as scrolledtext
import re

# --- GBA Virtual CPU State ---
REGS = {f"r{i}": 0 for i in range(16)}  # 16 general-purpose registers
CPSR = {'N': 0, 'Z': 0, 'C': 0, 'V': 0, 'MODE': 'USR'}  # Current Program Status Register
MEM = [0] * (32 * 1024)  # 32KB IWRAM
PC = 0
RUNNING = False
PROGRAM = []
LABELS = {}

# --- CPU Reset ---
def reset_cpu():
    global REGS, MEM, PC, RUNNING, PROGRAM, LABELS, CPSR
    REGS = {f"r{i}": 0 for i in range(16)}
    CPSR = {'N': 0, 'Z': 0, 'C': 0, 'V': 0, 'MODE': 'USR'}
    MEM = [0] * (32 * 1024)
    PC = 0
    RUNNING = False
    PROGRAM = []
    LABELS = {}

# --- Parser & Loader ---
def parse_asm(asm_code):
    global PROGRAM, LABELS
    PROGRAM = []
    LABELS = {}
    lines = asm_code.strip().split('\n')
    for idx, line in enumerate(lines):
        line = line.split(';')[0].strip()  # Remove comments
        if not line:
            continue
        label_match = re.match(r"^([A-Za-z_][\w]*):$", line)
        if label_match:
            LABELS[label_match.group(1)] = len(PROGRAM)
        else:
            PROGRAM.append(line)

# --- Instruction Fetch & Execution ---
def fetch():
    global PC, PROGRAM
    if PC >= len(PROGRAM):
        return None
    return PROGRAM[PC]

def update_flags(val):
    CPSR['Z'] = int(val == 0)
    CPSR['N'] = int((val & (1 << 31)) != 0)

def step(output_callback):
    global PC, RUNNING, PROGRAM, REGS, MEM, LABELS, CPSR
    if PC >= len(PROGRAM):
        RUNNING = False
        return False
    line = PROGRAM[PC]
    tokens = line.replace(',', ' ').split()
    if not tokens:
        PC += 1
        return True
    instr = tokens[0].upper()
    try:
        if instr == "MOV":
            REGS[tokens[1]] = get_value(tokens[2])
            update_flags(REGS[tokens[1]])
        elif instr == "ADD":
            result = REGS[tokens[1]] + get_value(tokens[2])
            CPSR['C'] = int(result > 0xFFFFFFFF)
            REGS[tokens[1]] = result & 0xFFFFFFFF
            update_flags(REGS[tokens[1]])
        elif instr == "SUB":
            result = REGS[tokens[1]] - get_value(tokens[2])
            CPSR['C'] = int(REGS[tokens[1]] >= get_value(tokens[2]))
            REGS[tokens[1]] = result & 0xFFFFFFFF
            update_flags(REGS[tokens[1]])
        elif instr == "LDR":
            addr = get_value(tokens[2])
            REGS[tokens[1]] = MEM[addr]
            update_flags(REGS[tokens[1]])
        elif instr == "STR":
            addr = get_value(tokens[2])
            MEM[addr] = REGS[tokens[1]]
        elif instr == "JMP":
            tgt = tokens[1]
            if tgt.isdigit():
                PC = int(tgt)
                return True
            elif tgt in LABELS:
                PC = LABELS[tgt]
                return True
        elif instr == "CJMP":
            reg = tokens[1]
            tgt = tokens[2]
            if REGS[reg] != 0:
                if tgt in LABELS:
                    PC = LABELS[tgt]
                    return True
        elif instr == "CMP":
            result = REGS[tokens[1]] - get_value(tokens[2])
            update_flags(result)
        elif instr == "PRN":
            output_callback(f"{tokens[1]} = {REGS[tokens[1]]}")
        elif instr == "HLT":
            output_callback("HALT")
            RUNNING = False
            return False
        elif instr == "MODE":
            CPSR['MODE'] = tokens[1].upper()
        else:
            output_callback(f"Unknown instr: {instr}")
    except Exception as e:
        output_callback(f"Error: {e}")
    PC += 1
    return True

def get_value(x):
    if x in REGS:
        return REGS[x]
    elif x.startswith("0x"):
        return int(x, 16)
    else:
        return int(x)

# --- Tkinter GUI ---
class ASMJourney01(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ASMJourney 01")
        self.geometry("1100x650")
        self.create_widgets()
        self.reset_all()

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

    def generate_assembly(self):
        prompt = self.prompt_box.get("1.0", tk.END).strip()
        lines = prompt.split('\n')
        assembly = []
        known_mnemonics = ["MOV", "ADD", "SUB", "LDR", "STR", "JMP", "CJMP", "CMP", "PRN", "HLT", "MODE"]
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.endswith(":"):
                assembly.append(line)  # Preserve labels
            else:
                first_word = line.split()[0].upper() if line.split() else ""
                if first_word in known_mnemonics:
                    assembly.append(line)  # Pass assembly instructions directly
                else:
                    asm_line = self.parse_command(line)
                    if asm_line:
                        assembly.append(asm_line)
                    else:
                        assembly.append(f"; Unrecognized command: {line}")
        
        self.code_box.delete("1.0", tk.END)
        self.code_box.insert(tk.END, "\n".join(assembly))
        self.notebook.select(1)  # Switch to Assembly tab

    def parse_command(self, command):
        patterns = [
            (r"(?:load|move|set) (?P<value>\d+|0x[0-9a-fA-F]+) (?:to|into) (?P<register>r\d{1,2})",
             lambda m: f"MOV {m.group('register')}, {m.group('value')}"),
            (r"add (?P<value>\w+) to (?P<register>r\d{1,2})",
             lambda m: f"ADD {m.group('register')}, {m.group('value')}"),
            (r"subtract (?P<value>\w+) from (?P<register>r\d{1,2})",
             lambda m: f"SUB {m.group('register')}, {m.group('value')}"),
            (r"store (?P<register>r\d{1,2}) at (?P<address>\d+|0x[0-9a-fA-F]+)",
             lambda m: f"STR {m.group('register')}, {m.group('address')}"),
            (r"load from (?P<address>\d+|0x[0-9a-fA-F]+) to (?P<register>r\d{1,2})",
             lambda m: f"LDR {m.group('register')}, {m.group('address')}"),
            (r"jump to (?P<label>\w+)",
             lambda m: f"JMP {m.group('label')}"),
            (r"if (?P<register>r\d{1,2}) is not zero, jump to (?P<label>\w+)",
             lambda m: f"CJMP {m.group('register')}, {m.group('label')}"),
            (r"compare (?P<register>r\d{1,2}) (?:to|with) (?P<value>\w+)",
             lambda m: f"CMP {m.group('register')}, {m.group('value')}"),
            (r"print (?P<register>r\d{1,2})",
             lambda m: f"PRN {m.group('register')}"),
            (r"halt",
             lambda m: "HLT"),
            (r"set mode to (?P<mode>\w+)",
             lambda m: f"MODE {m.group('mode')}"),
        ]
        
        for pattern, generator in patterns:
            match = re.match(pattern, command, re.IGNORECASE)
            if match:
                return generator(match)
        return None

    def load_code(self):
        code = self.code_box.get("1.0", tk.END)
        parse_asm(code)
        self.write_output("Code loaded.\n")
        self.update_state()

    def write_output(self, msg):
        self.output_box.config(state=tk.NORMAL)
        self.output_box.insert(tk.END, msg + "\n")
        self.output_box.see(tk.END)
        self.output_box.config(state=tk.DISABLED)

    def update_state(self):
        self.regs_box.config(state=tk.NORMAL)
        self.regs_box.delete("1.0", tk.END)
        for k, v in REGS.items():
            self.regs_box.insert(tk.END, f"{k}: {v}\n")
        self.regs_box.config(state=tk.DISABLED)
        
        self.cpsr_box.config(state=tk.NORMAL)
        self.cpsr_box.delete("1.0", tk.END)
        cpsr_str = " ".join([f"{f}={CPSR[f]}" for f in ['N', 'Z', 'C', 'V', 'MODE']])
        self.cpsr_box.insert(tk.END, cpsr_str)
        self.cpsr_box.config(state=tk.DISABLED)
        
        self.mem_box.config(state=tk.NORMAL)
        self.mem_box.delete("1.0", tk.END)
        mem_str = " ".join(f"{b:02x}" for b in MEM[:128])
        self.mem_box.insert(tk.END, mem_str)
        self.mem_box.config(state=tk.DISABLED)

    def run_program(self):
        self.load_code()
        global RUNNING, PC
        RUNNING = True
        while RUNNING and PC < len(PROGRAM):
            step(self.write_output)
            self.update_state()

    def step_once(self):
        if not PROGRAM:
            self.load_code()
        step(self.write_output)
        self.update_state()

    def reset_all(self):
        reset_cpu()
        self.output_box.config(state=tk.NORMAL)
        self.output_box.delete("1.0", tk.END)
        self.output_box.config(state=tk.DISABLED)
        self.prompt_box.delete("1.0", tk.END)
        self.code_box.delete("1.0", tk.END)
        self.prompt_box.insert(tk.END,
"""load 0x10 into r0
set r1 to 0x20
add r0 to r1
compare r0 with 0x30
print r0
print r1
set mode to SVC
halt""")
        self.update_state()

if __name__ == "__main__":
    app = ASMJourney01()
    app.mainloop()
