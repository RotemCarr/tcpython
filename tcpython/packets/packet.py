"""
Base class for packets
defines packet chaining operations and layers
"""

class Packet:
    def __init__(self, layers: list, raw: bytes, *args, **kwargs):
        self.layers = layers
        self.raw = raw

    def __rtruediv__(self, other):
        raw = other.raw + self.raw
        layers = self.layers
        layers.extend(other.layers)
        return Packet(layers, raw)
