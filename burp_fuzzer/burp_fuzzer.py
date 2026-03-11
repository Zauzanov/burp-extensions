from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

from java.util import List, ArrayList

import random

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.registerIntruderPayloadGeneratorFactory(self)
        return
    
    def getGeneratorName(self):
        return "BOOM Payload Generator"
    
    def createNewInstance(self, attack):
        return BurpFuzzer(self, attack)


class BurpFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.max_payloads = 10
        self.num_iterations = 0
        
        return 
    
    def hasMorePayloads(self):
        if self.num_iterations == self.max_payloads:
            return False
        else: 
            return True
        
    def getNextPayload(self, current_payload):
        # Convert to a string
        payload = "".join(chr(x) for x in current_payload)

        # Call our simple method to modify the POST request
        payload = self.mutate_payload(payload)

        # Increment the number of attempts
        self.num_iterations += 1

        return payload
    
    def reset(self):
        self.num_iterations = 0
        return

    def mutate_payload(self, original_payload):
        # Choose a simple fuzzing method(we can even call an external script)
        picker = random.randint(1, 3)

        # Choose a random offset in modified payload
        offset = random.randint(0, len(original_payload)-1)

        front, back = original_payload[:offset], original_payload[offset:]

        # Trying to inject SQL code with a random offset
        if picker == 1:
            front += "'"
        
        # In addition to this, we are attempting an XSS-attack
        elif picker ==2:
            front += "<script>alert('BooM!BOOM!BAM!');</script>"
        
        # Duplicate a random fragment of the original payload
        elif picker == 3:
            chunk_length = random.randint(0, len(back)-1)
            repeater = random.randint(1, 10)
            for _ in range(repeater):
                front += original_payload[:offset + chunk_length]
        
        return front + back