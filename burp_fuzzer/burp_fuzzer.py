from burp import IBurpExtender                                                                  # The entry point for every Burp extension. 
from burp import IIntruderPayloadGeneratorFactory                                               #  A payload generator provider to create a generator object. 
from burp import IIntruderPayloadGenerator                                                      # The actual payload generator. 

from java.util import List, ArrayList                                                           # Imports Java classes into this Jython script.

import random                                                                                   # To give our fuzzing a randomized nature. 


# Burp looks for a class named BurpExtender that implements IBurpExtender.
class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):                            # This class implements two Burp interfaces: The first as an entry point for the extension; The second as a factory that creates Intruder payload generators.
    def registerExtenderCallbacks(self, callbacks):                                             # Extension registration; `callbacks` - Burp's API object, gives our extension access to Burp functionality.
        self._callbacks = callbacks                                                             # Store the callbacks object inside the class so we can use it later; Underscores stands for internal use.
        self._helpers = callbacks.getHelpers()                                                  # Burp's helpers object containing utility methods: converting bytes to strings; analyzing HTTP reqs/resps and so on. 

        callbacks.registerIntruderPayloadGeneratorFactory(self)                                 # Registers this extension as a payload generator factory for Intruder.  
        return
    
    # Generator display name. 
    def getGeneratorName(self):
        return "BOOM Payload Generator"                                                         # Burp uses this method to dispay our generator's name in the Intruder UI.
    
    # Creating a generator instance.
    def createNewInstance(self, attack):                                                        # Burp calls this method, when Intruder starts an attack and uses this extension. 
        return BurpFuzzer(self, attack)                                                         # Creates and returns a new payload generator object. Each attack gets its own state: own counter, own settings and own execution context. 


# This class generates payloads. 
# It implements IIntruderPayloadGenerator, 
# as Burp expects it to provide the following methods.
class BurpFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):                                                       # This is the constructor. It runs when we do: BurpFuzzer(self, attack).
        self._extender = extender                                                               # We store a reference to the main extension object. That gives our generator access to anything stored there. 
        self._helpers = extender._helpers                                                       # Copies Burp helpers from th main extension into this generator. 
        self._attack = attack                                                                   # Stores the Intruder attack context: could be useful for attack-specific behavior.
        self.max_payloads = 10                                                                  # Sets a hard limit: the generator will produce 10 payloads total. 
        self.num_iterations = 0                                                                 # Initializes a counter tracking how many payloads have already been generated. 
        
        return 
    
    # Checks whether we've reached the max number of fuzzing iterations.
    def hasMorePayloads(self):
        if self.num_iterations == self.max_payloads:
            return False                                                                        # We use a Boolean here, as this method itself is supposed to answer a yes/no question. 
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