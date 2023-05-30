from  ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os


program = currentProgram
decompinterface = DecompInterface()
decompinterface.openProgram(program);
functions = program.getFunctionManager().getFunctions(True)

cwd=os.getcwd()
# nm=cwd.split("/")
# rpath='/'+nm[1]+'/'+nm[2]+'/'+nm[3]+'/decompiled/ut/'

for function in list(functions):
	tokengrp = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
	funct=(tokengrp.getDecompiledFunction().getC())
	# print(tokengrp.getDecompiledFunction().getC())
	path='static/decompiled/ut/'+str(function)+".c"
	fp=open(path,'w')
	fp.write(funct)
