import pickle
from enum import Enum

class MessageType(Enum):
    GET_KEY_FROM_KDS = "get_key_from_kds"
    GET_KEY_FROM_KDS_RESPONSE = "get_key_from_kds_response"
    INITIAL_COMMUNICATION_REQUEST_TO_TARGET = "icrtt"
    ACK_TARGET_NONCE2 = "atn2"

class Message:
    sender = None
    message = None
    time = None

    def __init__(self, sender, message, time):
        self.sender = sender
        self.message = message
        self.time = time

# 1. First request to kds
class GetKeyFromKDSResponse(Message):
    public_key = None
    original_message = None
    signature = None

    def __init__(self, sender, message, time, public_key, original_message):
        super().__init__(sender, message, time)
        self.public_key = public_key
        self.original_message = original_message
    
    def add_signature(self,signature):
        self.signature = signature

# 3. Initial request to target
class InitialCommunicationRequestToTarget(Message):
    id = None
    nonce = None

    def __init__(self, sender, message, time, id, nonce):
        super().__init__(sender, message, time)

        self.id = id
        self.nonce = nonce

# 6. Response to initial request to target
class InitialCommunicationRequestToTargetResponse(Message):
    nonce = None
    nonce2 = None

    def __init__(self, sender, message, time, nonce, nonce2):
        super().__init__(sender, message, time)
        self.nonce = nonce
        self.nonce2 = nonce2

# 7. Acknowledge nonce 2
class AckNonce2(Message):
    nonce2 = None

    def __init__(self, sender, message, time, nonce2):
        super().__init__(sender, message, time)
        self.nonce2 = nonce2   
