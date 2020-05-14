# Emulator UI for Ghidra

Fairly jank right now, made for a project in CMU's 14-819 reverse engineering course.

# Usage

The EmulatorUi must be first enabled from `File > Configure > Configure All Plugins`.  Then, a window with multiple
sub-panes should be present in Ghidra's interface.

From there, the interface is made up of 6 main tabs and then 4 buttons in the top right.  From left to right the buttons
are:

- Restart (green arrows in a circle) - restarts the emulator on the current program into a default state, leaves current
viewing options and hook script intact.  Needed to reload the hook script.
- Goto (up-left facing arrow): set the program counter register to be at the address being pointed at by the cursor in the assembly listing.
- Step (yellow right arrow): run a single opcode, advancing or jumping the PC, updating memory, registers, or running a hook
if applicable.
- Run (blue right arrow): runs the emulator starting at the current program counter until it hits a breakpoint.  Both run and step are
threaded, and can be cancelled if it is taking too long.

The functions of the panels are as follows

### Dev Log

Used for development

### Register Table

Contains a way of viewing register contents of the emulator.  The leftmost column is what register each row corresponds
to, and in order to add a register to the view type/select it from the dropdown of the bottom (empty) row, and to change
a row just change the value in this first column.  The raw value column is its raw value interpreted in hex.  The type
column can be used to select a type for the register, which will then affect what is displayed in the interpreted column.

Entries in the `Raw Value` column can be edited to a hex integer value to modify the value of the register in the
emulator state.

### Locals Table

This needs work done on it to better support decompiler variable naming.  Right now, it only supports getting
raw values of variables defined in the listing, which can be a subset of the local variables defined
in the decompiler.  With the exception of not being able to change what variables are viewed (since presumably
there is no need to hide variables unlike with the many registers in most architectures), this functions
identically to the register table.

### Memory Changes Table

This is mostly useful in dealing with self-modifying code.  If in the course of running the emulator, memory that
overlaps with the listing display is modified, the sections that are modified will show up in this table as a row.
To move the changes in the emulator to the listing, presumably to be able to analyze self-modified code, edit
the second column to be "COMMIT" and then enter.  This can be undone as any other Ghidra action with Ctrl+Z.

### Breakpoint Table

In a similar method to the register table, edit the first column in order to set, modify, or delete
breakpoints in the emulator.  When a run command on the emulator ends on a breakpoint, the Hit column
of this table for the corresponding breakpoint should increase by 1.

### Hook Manager

This pane is simply a text editor, which runs python code in it on restart of the emulator.  While all of the
standard Jython are present, many utilities are added in order to make the process of hooking functions easier.

The `@Hook(function_name)` function decorator adds a breakpoint to the first address of the symbol `function_name`,
that when hit runs the function it decorates with the same arguments as what the function would have been called with.
After running the python function, it corrects the stack pointer back to where it should be (though changing the
instruction pointer and setting the return register must still be done in Python) and continues running the
emulator if it was given a run command, leaving it as it is with a step command.  Examples of function
hooking are provided below.

The `mem` object allows for bytes to be got and set in the primary address space of the program as if it were
an array of bytes.  For example,
`mem[0x404040] = ord('a')` will set the byte at address `404040` to be 'a' in the emulator's memory.  Also,
`ghidra.util.Msg.showInfo(None, None, "info", str(mem[0x402020]))` uses Ghidra's Msg class to display an alert
of the byte in emulator memory at `402020`, as expected.

The `reg` object allows for register values to be accessed and set, as if it were a dictionary of the emulator's
current registers.  The register names are the same as those in the register table, case-sensitive.  For example,
`reg["EAX"] = 0` is useful in setting the return (EAX) value of a function to be 0, if that is the desired
functionality.  `reg["ESP"] += 4` increments the stack pointer by 4 on x86, as expected.

The `emu` object is direct access to the underlying EmulatorHelper object that is currently running.  This
provides access to things such as `emu.readStackValue(offset, size, signed (bool))`.  Therefore, an x86 return
function that can be called to emulate a `ret` instruction can be written as follows:

```python
def x86ret():
	reg["EIP"] = emu.readStackValue(0, 4, False)
	reg["ESP"] += 4 # We only need to increment 4 since the hook manager handles the rest
			# of the stack purge depth
```

This allows for other architectures that do not use stack-based returning (such as MIPS, PPC, and RISC-V)
to be hooked without much hassle, as a RISC-V `ret` psuedo-instruction can be done as follows.  This was
extremely useful in the Hack-At-Sec competition, where the tooling around their custom chip would take
almost half an hour to run a simple test, so quickly emulating RISC-V (assuming their chip was correct)
to hunt for vulnerabilities was valuable.

```python
def riscvret():
	reg["PC"] = reg["R1"] # r1 is the conventional link register, though nothing enforces this
```

Even though RISC-V has no integration into Ghidra by default, but it is actually very simple to
write a single Sleigh script that gives it full integration into disassembly, decompilation, and now emulation.

# Installation

The extension installs like any other Ghidra extension.  In the initial tool, go to File > Install Extension,
then add the dist/ghidra_*_EmulatorUi.zip file.  Ghidra should handle the rest after a restart.

# Examples

## Limitations

First a note on limitations.  As I write later: the emulation has a massive speed overhead compared to native
code execution.  Also, it does not understand OS information (i.e., syscalls, API functions that you haven't
linked or given a hook for), so it should mostly be used for functions that do not rely heavily on OS
utilities.


## Hook script example

I removed a bunch of these examples that were specific to class files/project.  Broadly, the hook script can be used to hook and emulate the functions that _should_ be in the standard library, so here's the portion of one of mine that did that:

My hook script:

```python
# The following is pretty much universally useful,
# will hook and provide reasonable implementations of common
# C library functions, also showing how the hook file has
# very easy integration with the emulator state via the 
# @Hook decorator, and the reg, emu, and mem variables.

heapbase = reg["ESP"] - 0x1000000
heapptr = heapbase

def x86ret():
	reg["EIP"] = emu.readStackValue(0, 4, False)
	reg["ESP"] += 4

@Hook("memcpy")
def hookmemcpy(t,f,l):
	for i in range(l):
		mem[t+i] = mem[f+i]
	x86ret()

@Hook("GetProcessHeap")
def hookgph():
	x86ret()

@Hook("strcpy")
def hookstrcpy(t, f):
	i = 0
	while mem[f+i] != 0:
		mem[t+i] = mem[f+i]
		i += 1
	x86ret()

@Hook("HeapFree")
def hookheapfree(*a):
	x86ret()

@Hook("HeapAlloc")
def hookheapalloc(heapname, idk, size):
	global heapptr
	reg["EAX"] = heapptr
	heapptr += size
	x86ret()

@Hook("atoi")
def hookatoi(buf):
	num = 0
	i = 0
	while True:
		cur = mem[buf+i]
		if cur < ord('0') or cur > ord('9'):
			break
		num = num * 10 + cur - ord('0')
		i += 1
	reg["EAX"] = num
	x86ret()

@Hook("memset")
def hookmemset(ptr, val, amt):
	for i in range(amt):
		mem[ptr+i] = val
	x86ret()


@Hook("Sleep")
def hooksleep(amt):
	x86ret()

@Hook("skip_this")
def hookskipthis(*a):
	x86ret()
```



