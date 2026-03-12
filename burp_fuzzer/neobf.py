from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

import random


class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Custom Intruder Payload Generator")
        callbacks.registerIntruderPayloadGeneratorFactory(self)

    def getGeneratorName(self):
        return "ZAAAAAP Payload Generator"

    def createNewInstance(self, attack):
        return BurpFuzzer(self, attack)


class BurpFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.max_payloads = 10
        self.num_iterations = 0

    def hasMorePayloads(self):
        return self.num_iterations < self.max_payloads

    def getNextPayload(self, baseValue):
        # baseValue is a byte[] from Burp
        if baseValue is None:
            payload = ""
        else:
            payload = self._helpers.bytesToString(baseValue)

        mutated = self.mutate_payload(payload)
        self.num_iterations += 1

        return self._helpers.stringToBytes(mutated)

    def reset(self):
        self.num_iterations = 0

    def mutate_payload(self, original_payload):
        # Handle empty payloads cleanly
        if not original_payload:
            original_payload = "1"

        picker = random.randint(1, 3)
        offset = random.randint(0, len(original_payload))

        front = original_payload[:offset]
        back = original_payload[offset:]

        if picker == 1:
            front += "'"

        elif picker == 2:
            front += "<script>alert('BooM!BOOM!BAM!');</script>"

        elif picker == 3:
            if len(back) > 0:
                chunk_length = random.randint(1, len(back))
                repeater = random.randint(1, 3)
                chunk = back[:chunk_length]
                front += chunk * repeater
            else:
                front += "' OR '1'='1"

        return front + back
