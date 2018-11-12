import socket
import threading
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
BUFFER_SIZE = 1024
NUM_USERS = 10

#dictionary that contains names
client_queue = dict()

#dictionary that contains the encryption key 
encryption_queue = dict()

#get the port number from the user
port_check = True
while (port_check):
	port_input = input('Port number: ')
	try:
		port = int(port_input)
	except Exception as e:
		print("Please enter the port in numbers.")
		continue			
	if(port > 1024 and port < 65535):
		port_check = False

#create the socket
sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sockfd.bind(('',port)) 

#read in the private key
with open("myprivatekey.pem",mode="rb") as file:
	raw_priv_key = file.read()

#create the private key object
private_key = serialization.load_pem_private_key(
	raw_priv_key, 
	password=None, 
	backend=default_backend()
)


print("Sever is on.")
		
def Socket_Thread():

	# create the socket we are going to recieve from
	connected_socket, addr = sockfd.accept()

	#read data - fist message will always be the sym key
	raw_in = connected_socket.recv(BUFFER_SIZE)
	sym_key = decrypt_string(raw_in) 
	fernet = Fernet(sym_key.decode())

	while True:

		data = connected_socket.recv(BUFFER_SIZE)

		#if there is anything in the message
		if data:
			printable = ""

			#create the encyption object
			if(connected_socket in client_queue.keys()):
				fernet = Fernet(encryption_queue[connected_socket])
			else:
				encryption_queue[connected_socket] = sym_key
			
			# decrypt the message 
			dec_data = fernet.decrypt(data)
			printable = dec_data.decode()

			#if it is a special request
			if(printable[0] == '~'):

				#requested client list
				if('clientlist' in printable):
					print("asked for list")

					#create the client list
					client_list = printable + '~'
					for elm in client_queue.values():
						client_list = client_list + elm + '~'

					#send the list
					send_val =fernet.encrypt(str.encode(client_list))
					connected_socket.send(send_val)

				#sent a username
				elif('username' in printable):

					#parse out the username
					username_location = (printable.rfind('~') + 1)
					username = printable[username_location:]
					print("New user: "+ username)

					# update the list of clients
					client_queue[connected_socket] = username

				#attempted to send a pm
				elif('privatemessage' in printable):

					#parse out message and dest
					printable = printable.replace("~privatemessage~","")
					tl = printable.find('~')
					username = printable[0:tl]
					message = printable[(tl+1):]

					response = "Message sent to "+username

					#if valid username send it
					if username not in client_queue.values():
						response = "Message not sent. " + username +" not a valid recepiant."
					else:
						for socket, name in client_queue.items():
							if name == username:
								print("private message sent")

								#create a temp fernet object to send the message too
								temp_fernet = Fernet(encryption_queue[socket])

								#encrypt and send
								send_val = temp_fernet.encrypt(str.encode(message + "~Private " + client_queue[connected_socket]))
								socket.send(send_val)

						#encrypt and send
						send_val =fernet.encrypt(str.encode(response))
						connected_socket.send(send_val)

				#kick user request
				elif('kickuser' in printable):

					#parse out info
					printable = printable.replace("~kickuser~","")
					tl = printable.find('~')
					username = printable[0:tl]
					message = "~kicked~" + printable[(tl+1):]
					response = "Kicked user "+username

					#if valid user, turn off their terminal
					# remove from client list
					if username not in client_queue.values():
						print("user " + username + "kicked")
						response = "User not kicked. " + username +" is not a valid user."
					else:
						for socket, name in client_queue.items():
							if name == username:

								#create a temp fernet object to send the message too
								temp_fernet = Fernet(encryption_queue[socket])
								
								#encrypt and send
								send_val =temp_fernet.encrypt(str.encode(message))
								socket.send(send_val)

								#remove the client from our lists
								del client_queue[socket]
								del encryption_queue[socket]
								break

						#encrypt and send
						send_val =fernet.encrypt(str.encode(response))
						connected_socket.send(send_val)
						continue
			else:

				#if they exited the program 
				if(printable.lower() == 'quit'):
					print("Client disconnected.")

					#remove from out lists
					del client_queue[connected_socket]
					del encryption_queue[connected_socket]


				#any thing else is a valid message
				else:
					#output the message on the server. mostly for testing and proof of concept
					print(client_queue[connected_socket] + " > " + printable)

					#if there are any clients
					if client_queue:
						#send the message to all clients
						for client_sock in client_queue.keys():
							if client_sock != connected_socket:
								
								#create a temp fernet object to send the message too
								temp_fernet = Fernet(encryption_queue[client_sock])
								
								#append with user name, encrypt and send
								send_val =temp_fernet.encrypt(str.encode(printable + "~" + client_queue[connected_socket]))
								client_sock.send(send_val)

def decrypt_string(data):
	
	#Decrypting our example text
	return_value = private_key.decrypt(
	# Text to be decrypted
	data,
	padding.OAEP(
		# Make sure that the hash and padding classes are the same as the encryption
		mgf=padding.MGF1(algorithm=hashes.SHA1()),
		algorithm=hashes.SHA1(),
		label=None
	))
	return(return_value)


#allow for up to ten users
sockfd.listen(NUM_USERS)
for itr in range(NUM_USERS):
	#create the socket thread, make sure daemon is false, so we can keep running
	sock_thread = threading.Thread(target = Socket_Thread)
	sock_thread.daemon = False
	sock_thread.start()