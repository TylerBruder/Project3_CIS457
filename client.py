import socket
import threading
import ipaddress
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


BUFFER_SIZE = 1024
PASSWORD = "1234"

#User input the port num
port_check = True
while (port_check):
	port_input = input('Port number: ')
	try:
		port = int(port_input)
	except Exception as e:
		print("Please enter the port in numbers.")
	if(port > 1024 and port < 65535):
		port_check = False

#user input the IP address
ip_check = True
while(ip_check):
	ip = input('Destination IP: ')
	try:
		ipaddress.ip_address(ip)
		ip_check = False
	except Exception as e:
		print("Please enter a valid IP address.")

user_name = ""

#determine the source of the server
dest = (ip,port)

#create the socket
sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sockfd.connect((dest))

#read in public key from file
with open("mypublickey.pem",mode="rb") as file:
	pub_key = load_pem_public_key(file.read(),	backend=default_backend())

#create the symmetric key
sym_key = Fernet.generate_key()
fernet = Fernet(sym_key)

# encrypt the symmetric key
enc_sym_key = pub_key.encrypt(
	# Text to be encrypted
	sym_key,
	padding.OAEP(
		# MGF - Mask generation function
		mgf=padding.MGF1(algorithm=hashes.SHA1()),
		algorithm=hashes.SHA1(),
		label=None
	)
)

#send the symetric key
sockfd.send(enc_sym_key)

#when the user wants to see the menu
def User_Menu():
	while(True):

		Print_Menu()
		ui = input("> ")

		#validate input
		try:
			menu_selection = int(ui)
		except Exception as e:
			print("Please Enter a valid input\n") 
			continue
		if(menu_selection<1 or menu_selection>5):
			print("Please Enter a valid input\n") 
			continue
		else:
			#client list
			if menu_selection == 1:
				request = "~clientlist"
				send_val =fernet.encrypt(str.encode(request))
				sockfd.send(send_val)
			#PM
			elif menu_selection == 2:
				target = input('Target username > ')
				message = input('Message > ')
				request = "~privatemessage~"+target+'~'+message
				send_val =fernet.encrypt(str.encode(request))
				sockfd.send(send_val)
			#admin menu
			elif menu_selection == 4:
				Print_Admin()
			#quit program
			elif menu_selection == 5:
				send_val = fernet.encrypt(b"quit")
				sockfd.send(send_val)
				os._exit(0)
			break	

#Print the user menu
def Print_Menu():
	print("\n========== Menu ==========\n"+
			"1. List of clients\n"+
			"2. Message client\n"+
			"3. Message all clients\n"+
			"4. Admin Menu\n"+
			"5. exit\n")

#print and run the admin menu
def Print_Admin():
	print("===Admin Menu===")
	ctr = 0
	while(True):
		pwa = input("Password > ")
		#password checking
		if(pwa != PASSWORD):
			ctr = ctr + 1
			if(ctr > 2):
				print("Password failed goodbye")
				return()
			else:
				print("Password failed try again")
		else:
			while(True):
				#input validation
				print("1. Kick client\n" + 
					"2. Exit\n")
				ai = input("\n> ")
				try:
					selection = int(ai)
				except Exception as e:
					print("Please Enter a valid input\n") 
					continue
				if(selection<1 or selection>2):
					print("Please Enter a valid input\n") 
					continue
				#kick user
				if(selection == 1):
					target = input('Kick user > ')
					message = input('Reason > ')
					request = "~kickuser~"+target+'~'+message
					send_val =fernet.encrypt(str.encode(request))
					sockfd.send(send_val)
					return()
				#leave menu
				elif(selection == 2):
					return()
			break

#send a username to the server
def New_Username():
	user_name = input("User name > ")
	message = "~username~" + user_name
	send_val =fernet.encrypt(str.encode(message))
	sockfd.send(send_val) 

#the function that the socket recevie thread will run
def Socket_Thread():
	New_Username()
	print("Connected to server on a public chanel.")
	print("Type 'menu' to see options.")

	while True:

		#users raw message
		data = sockfd.recv(BUFFER_SIZE)

		#if there is no data next
		if not data:
			continue

		#readable message
		plaintext = fernet.decrypt(data)
		printable = plaintext.decode()
		
		#if you were sent a special request
		if(printable[0] == '~'):

			#print the client list
			if("clientlist" in printable):
				printable = printable.replace('~','\n')
				print(printable)

			#Youve been kicked
			elif("kicked" in printable): 
				printable = printable.replace("~kicked~","")
				print("You have been kicked.")
				print("Admin reason: " + printable)
				os._exit(0)

		#print users message
		else:
			tl = printable.find('~')
			other_username = "Server"
			if(tl > 0):
				other_username = printable[(tl+1):]
				printable = printable[0:tl]

			#if the message was quit, quit
			if(printable.lower() == 'quit'):
				print("Server disconnected. Goodbye.")
				os._exit(0)

			print("["+other_username + "] " + printable)

#the function that our input will run
def Input_Thread():
	while True:
		#read message
		message = input("\n")
		if not message:
			continue

		text_message = str.encode(message)

		#if the message was quit, quit
		if(message.lower() == 'quit'):
			send_val =fernet.encrypt(text_message)
			sockfd.send(send_val)
			print("\nClient disconnected.")
			os._exit(0)

		#print the menu options
		elif(message.lower() == 'menu'):
			User_Menu()

		#send user message
		else:
			send_val =fernet.encrypt(text_message)
			sockfd.send(send_val)

#create the socket thread, make sure daemon is false, so we can keep running
sock_thread = threading.Thread(target = Socket_Thread)
sock_thread.daemon = False

#create the input thread
input_thread = threading.Thread(target = Input_Thread)
input_thread.daemon = False

sock_thread.start()
input_thread.start() 