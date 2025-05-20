import tkinter as tk
import tkinter.ttk as ttk
import tkinter.scrolledtext as scrolledtext
import re
import torch
import torch.nn as nn
from collections import defaultdict

# --- GBA Virtual CPU State ---
REGS = {f"r{i}": 0 for i in range(16)}
CPSR = {'N': 0, 'Z': 0, 'C': 0, 'V': 0, 'MODE': 'USR'}
MEM = [0] * (32 * 1024)
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
        line = line.split(';')[0].strip()
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

# --- RNN for Assembly Generation ---
class ASMGeneratorRNN(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super(ASMGeneratorRNN, self).__init__()
        self.hidden_size = hidden_size
        self.output_size = output_size
        self.rnn = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc = nn.Linear(hidden_size, output_size)

    def forward(self, x):
        out, _ = self.rnn(x)
        out = self.fc(out[:, -1, :])
        return out
