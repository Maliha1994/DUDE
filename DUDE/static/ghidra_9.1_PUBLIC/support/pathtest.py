import os

cwd=os.getcwd()
nm=cwd.split("/")
path='/'+nm[1]+'/'+nm[2]+'/'+nm[3]+'/decompiled/ut/'

print(path)