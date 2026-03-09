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
        return "Payload Generator"
    
    def createNewInstance(self, attack):
        return BurpFuzzer(self, attack)

class BurpFuzzer(IIntruderPayloadGenerator):
    def __int__(self, extender, attack):
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
    
    
