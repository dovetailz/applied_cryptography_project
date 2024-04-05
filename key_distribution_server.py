from pathlib import Path
import socket
import pickle
from messages import *
from colorama import Fore, Style
import json

KDS = "key_distribution_server"

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import asyncio
import threading

def sign_message(message):
    # Load or generate a private key
    with open("pki/key_distribution_server/kds_private_key.pem", "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    # Data to be signed
    data = message

    # Create a SHA-256 hash of the data
    hash = SHA256.new(data)

    # Sign the hash with the private key
    signature = pkcs1_15.new(private_key).sign(hash)

    return signature

def respond_get_key_from_kds(message):
    sender = message.sender
    public_key_file = None

    if sender == "alice":
        public_key_file = Path("pki/bob/bob_public_key.pem")
    elif sender == "bob":
        public_key_file = Path("pki/alice/alice_public_key.pem")
        pass
    else:
        raise RuntimeError("Unknown sender " + sender )
    
    pk_file = open(public_key_file)
    message = GetKeyFromKDSResponse(sender=KDS,message=MessageType.GET_KEY_FROM_KDS_RESPONSE,time=message.time,public_key=pk_file.read(),original_message=message.message)
    pk_file.close()
    return message

class TCPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    async def handle_client(self, reader, writer):
        print("Received client connection")
        while True:
            try:
                data = await reader.read(8000)
                if not data:
                    break

                loaded_obj = pickle.loads(data)
                message = Message(loaded_obj.sender, loaded_obj.message, loaded_obj.time)
                print(f"{Fore.CYAN}Received message:{message.message} from {message.sender}{Style.RESET_ALL}")
                
                response = None
                if message.message == MessageType.GET_KEY_FROM_KDS:
                    response = respond_get_key_from_kds(message)

                signature = sign_message(pickle.dumps(response))
                response.add_signature(signature)

                print(f"{Fore.CYAN}Sending response to message:{message.message} from {message.sender}{Style.RESET_ALL}")
                writer.write(pickle.dumps(response))


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

def start_server_in_thread(port):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server = TCPServer('127.0.0.1', port)
    asyncio.run(server.start_server())


if __name__ == "__main__":
    HOST = '127.0.0.1'  # Standard loopback interface address

    # Assuming 'data.json' is your JSON file
    with open('configuration.json', 'r') as file:
        data = json.load(file)

    # Create and start a thread for the server
    server_thread = threading.Thread(target=start_server_in_thread,args=[data.get("kds")["port"]])
    server_thread.start()