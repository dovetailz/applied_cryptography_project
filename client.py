import socket
from colorama import Fore, Style
import argparse
from datetime import datetime

from messages import *

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import asyncio
import threading
import time
import json
import random

class Communicator:
    name = None
    port = None
    host = '127.0.0.1'
    private_key = None
    kds_port = None
    kds_public_key = None
    kds_socket = None
    target_port = None
    target_socket = None
    target_public_key = None

    def __init__(self, name, port, kds_port, kds_public_key):
        self.name = name
        self.port = port
        self.kds_port = kds_port
        self.kds_public_key = kds_public_key

        if name == 'alice':
            private_key_file = 'pki/alice/alice_private_key.pem'
        else:
            private_key_file = 'pki/bob/bob_private_key.pem'

        with open(private_key_file, 'rb') as f:
            self.private_key = RSA.import_key(f.read())

    def set_target_public_key(self,public_key):
        self.target_public_key = public_key

    def set_kds_socket(self,socket):
        self.kds_socket = socket

    def set_target_socket(self, socket):
        self.target_socket = socket

    def set_target_port(self, port):
        self.target_port = port

    def get_target_name(self):
        if self.name == 'alice':
            return 'bob'
        else:
            return 'alice'
        
def connect_to_kds(host, port, client_name):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print(Style.BRIGHT + Fore.CYAN + "Connecting to key distribution server as " + client_name + Style.RESET_ALL)
    client_socket.connect((host, port))

    return client_socket

def connect_to_target(host, port, client_name):
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            print(Style.BRIGHT + Fore.CYAN + "Connecting to target server as " + client_name + " on port " + str(port) + Style.RESET_ALL)
            client_socket.connect((host, port))

            return client_socket
        except Exception as e:
            time.sleep(1)
            continue

# Encrypt data using the public key
def encrypt_data(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

# Decrypt data using the private key
def decrypt_data(encrypted_data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    return decrypted_data

# verify message was signed by kds
def verify_message(message, signature, public_key):
    # Data to be verified
    data = message

    # Create a SHA-256 hash of the data
    hash = SHA256.new(data)

    try:
        # Verify the signature
        pkcs1_15.new(public_key).verify(hash, signature)
    except (ValueError, TypeError):
        print(Fore.RED + "Signature is invalid." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + "Error occurred during signature verification:" + e + Style.RESET_ALL)    

# 1. Public key request of target
# 2. Response to public key request
def get_key_from_kds(client : Communicator):

    # current time
    current_time = datetime.now()
    time_string = current_time.strftime("%H:%M:%S")

    # generate MessageType.GET_KEY_FROM_KDS message
    message = Message(sender=client.name, message=MessageType.GET_KEY_FROM_KDS,time=time_string)
    print(f"{Style.BRIGHT}{Fore.CYAN}Sending message:{message.message} to key distribution server{Style.RESET_ALL}")

    # send message to kds
    client.kds_socket.send(pickle.dumps(message))

    # get kds response 
    data = client.kds_socket.recv(8000)
    print(f"{Style.BRIGHT}{Fore.CYAN}Received response for message:{message.message} from key distribution server{Style.RESET_ALL}")

    # reassemble message into GetKeyFromKDSResponse object
    loaded_obj = pickle.loads(data)
    message = GetKeyFromKDSResponse(loaded_obj.sender, loaded_obj.message, loaded_obj.time, loaded_obj.public_key, loaded_obj.original_message)

    
    # 1. validate that the kds has signed this message
    verify_message(pickle.dumps(message), loaded_obj.signature, client.kds_public_key)
    # 2. validate same request
    if message.original_message != MessageType.GET_KEY_FROM_KDS:
        raise RuntimeError(Fore.RED + "Failed message type validation " + message.original_message.value + Style.RESET_ALL)
    # 3. validate time
    if message.time != time_string:
        raise RuntimeError(Fore.RED + "Failed time validation" + Style.RESET_ALL)
    
    print(f"{Style.BRIGHT}{Fore.GREEN}Validated response for message:{message.message} was signed by key distribution server{Style.RESET_ALL}")
    return message.public_key

# 3. Initial request to target
def send_communication_request_to_target(client : Communicator):
    # current time
    current_time = datetime.now()
    time_string = current_time.strftime("%H:%M:%S")

    # generate nonce
    nonce = random.randint(0,1000)

    # generate MessageType.GET_KEY_FROM_KDS message
    message = InitialCommunicationRequestToTarget(sender=client.name, message=MessageType.INITIAL_COMMUNICATION_REQUEST_TO_TARGET,time=time_string, id=client.name, nonce=nonce)
    print(f"{Style.BRIGHT}{Fore.CYAN}Sending message:{message.message} to {client.get_target_name()}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{Fore.CYAN}Nonce is {nonce}{Style.RESET_ALL}")

    encrypted_message = encrypt_data(pickle.dumps(message), client.target_public_key)
    client.target_socket.send(encrypted_message)

    # get response from target
    encrypted_response = client.target_socket.recv(8000)
    decrypted_response = decrypt_data(encrypted_response, client.private_key)

    loaded_obj = pickle.loads(decrypted_response)

    if time_string != loaded_obj.time:
        print(f"{Style.BRIGHT}{Fore.RED} Time received from {client.get_target_name()} does not equal time that we generated")
        exit(-1)
    # time validation
    new_current_time = datetime.now()
    new_time_string = new_current_time.strftime("%H:%M:%S")
    new_current_datetime = datetime.strptime(new_time_string, "%H:%M:%S")
    received_datetime = datetime.strptime(time_string, "%H:%M:%S")
    
    time_difference = new_current_datetime - received_datetime
    time_difference = time_difference.total_seconds()
    if time_difference != 0:
        print(f"{Style.BRIGHT}{Fore.RED} Time received from {client.get_target_name()} is {time_difference}s old. May be a replay.")
        exit(-1)

    message = InitialCommunicationRequestToTargetResponse(loaded_obj.sender, loaded_obj.message, loaded_obj.time, loaded_obj.nonce, loaded_obj.nonce2)
    print(f"{Style.BRIGHT}{Fore.CYAN}Received response to:{message.message} from {client.get_target_name()}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{Fore.CYAN}Nonce is {message.nonce}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{Fore.CYAN}Nonce2 is {message.nonce2}{Style.RESET_ALL}")

    return message.nonce2

# 4. get public key of initiator
# 5. get response from kds
def handle_initial_communication_request(message, client : Communicator):
    target_public_key = get_key_from_kds(client)
    target_public_key = RSA.import_key(target_public_key)

    client.set_target_public_key(target_public_key)
    print(f"{Style.BRIGHT}{Fore.CYAN}Received public key for {client.get_target_name()}{Style.RESET_ALL}")

    try:
        encrypted_message = encrypt_data(pickle.dumps(message),client.target_public_key)
    except Exception as e:
        print(e)
    return encrypted_message

# 3. Receive request for initial communication
# 6.
class TCPServer:
    def __init__(self, host, port, client : Communicator):
        self.host = host
        self.port = port
        self.client = client

    async def handle_client(self, reader, writer):
        nonce2 = None

        while True:
            data = await reader.read(8000)
            if not data:
                break

            if self.client.name == 'alice':
                private_key_file = 'pki/alice/alice_private_key.pem'
            else:
                private_key_file = 'pki/bob/bob_private_key.pem'

            with open(private_key_file, 'rb') as f:
                private_key = RSA.import_key(f.read())

            try:
                decrypted_data = decrypt_data(data, private_key)
            except Exception as e:
                print(e)
            
            loaded_obj = pickle.loads(decrypted_data)
            message = Message(loaded_obj.sender, loaded_obj.message, loaded_obj.time)
            print(f"{Style.BRIGHT}{Fore.CYAN}Received message:{message.message} from {message.sender}{Style.RESET_ALL}")
            
            try:
                response = None
                # 3. Receive Request
                if message.message == MessageType.INITIAL_COMMUNICATION_REQUEST_TO_TARGET:
                    nonce2 = loaded_obj.nonce + random.randint(0,100)
                    message = InitialCommunicationRequestToTargetResponse(loaded_obj.sender, loaded_obj.message, loaded_obj.time, loaded_obj.nonce, nonce2)
                    # 6. Send response
                    response = handle_initial_communication_request(message, client)
                    
                elif message.message == MessageType.ACK_TARGET_NONCE2:
                    message = AckNonce2(loaded_obj.sender, loaded_obj.message, loaded_obj.time, loaded_obj.nonce2)
                    if nonce2 == message.nonce2:
                        print(f"{Style.BRIGHT}{Fore.GREEN}Successfully established communication channel with {client.get_target_name()}{Style.RESET_ALL}")
                    else:
                        print(f"{Style.BRIGHT}{Fore.RED}Failed nonce validation. Expected nonce:{nonce2} Actual nonce:{message.nonce2}{Style.RESET_ALL}. May be a replay of an old nonce.")
                    return
                writer.write(response)
                await writer.drain()
            except Exception as e:
                print(e)

        writer.close()

    async def start_server(self):
        server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        addr = server.sockets[0].getsockname()
        print(f"Server listening on {addr}")

        async with server:
            await server.serve_forever()

def start_server_in_thread(client : Communicator, config):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server = TCPServer('127.0.0.1', config.get(client.name)["port"], client)
    asyncio.run(server.start_server())

def ack_nonce2(client : Communicator, nonce2):
    # current time
    current_time = datetime.now()
    time_string = current_time.strftime("%H:%M:%S")

    message = AckNonce2(sender=client.name, message=MessageType.ACK_TARGET_NONCE2, time=time_string, nonce2=nonce2)
    encrypted_message = encrypt_data(pickle.dumps(message), client.target_public_key)
    print(f"{Style.BRIGHT}{Fore.CYAN}Sending nonce ack for nonce:{nonce2} to {client.get_target_name()}{Style.RESET_ALL}")

    client.target_socket.send(encrypted_message)

def secure_communication(client : Communicator):
    target_socket = connect_to_target(client.host, client.target_port, client.name)
    client.set_target_socket(target_socket)

    # 1. get public key from kds
    target_public_key = get_key_from_kds(client)
    target_public_key = RSA.import_key(target_public_key)

    client.set_target_public_key(target_public_key)
    print(f"{Style.BRIGHT}{Fore.CYAN}Received public key for {client.get_target_name()}{Style.RESET_ALL}")

    # 3. send communication message to target(bob or alice)
    nonce2 = send_communication_request_to_target(client)

    # 7. Acknowledge nonce2
    ack_nonce2(client, nonce2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Client side program for secure communication project')
    parser.add_argument('--client_name',choices=['alice', 'bob'],type=str,help='Name of client user', required=True)
    parser.add_argument('--server_only',action='store_true', help='Set the flag')

    args = parser.parse_args()

    # Assuming 'data.json' is your JSON file
    with open('configuration.json', 'r') as file:
        config = json.load(file)

    client_name = args.client_name
    client_port = config.get(client_name)['port']
    kds_port = config.get('kds')['port']

    with open("pki/key_distribution_server/kds_public_key.pem", "rb") as key_file:
        kds_public_key = RSA.import_key(key_file.read())

    client = Communicator(client_name, client_port, kds_port, kds_public_key)
    client.set_target_port(config.get(client.get_target_name())['port'])
    
    kds_socket = connect_to_kds(client.host, client.kds_port,client.name)
    client.set_kds_socket(kds_socket)

    # Create and start a thread for the server
    server_thread = threading.Thread(target=start_server_in_thread,args=[client, config])
    server_thread.start()

    if not args.server_only:
        secure_communication(client)

    