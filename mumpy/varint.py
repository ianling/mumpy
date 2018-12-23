import struct


# comparators for checking varint prefix
VARINT_7_BIT = 0b0
VARINT_14_BIT = 0b10
VARINT_21_BIT = 0b110
VARINT_28_BIT = 0b1110
VARINT_32_BIT = 0b111100
VARINT_64_BIT = 0b111101
VARINT_NEGATIVE_RECURSIVE = 0b111110
VARINT_NEGATIVE_2_BIT = 0b111111


class VarInt:
    def __init__(self, data=bytes()):
        self.data = data

    def _get_next_byte(self):
        next_byte = struct.unpack('!B', self.data[:1])[0]
        self.data = self.data[1:]
        return next_byte

    def encode(self):
        """
        Encodes data as a VarInt.

        Returns:
            bytes: the data encoded as a VarInt
        """
        if self.data < -0b11:       # negative recursive
            varint = VarInt(abs(self.data)).encode()
            return_value = b'\xf8' + varint
        elif self.data <= -0b1:     # negative 2-bit
            return_value = struct.pack('!B', 0b11111100 | abs(self.data))
        elif self.data <= 0x7F:     # 7-bit
            return_value = struct.pack('!B', self.data)
        elif self.data <= 0x3FFF:   # 14-bit
            return_value = struct.pack('!H', 0x8000 | self.data)
        elif self.data <= 0x1FFFFF:  # 21-bit
            return_value = struct.pack('!I', 0xC00000 | self.data)[1:]  # encode as 32-bit, but cut off the first 8 bits
        elif self.data <= 0xFFFFFFF:  # 28-bit
            return_value = struct.pack('!I', 0xE0000000 | self.data)
        elif self.data <= 0xFFFFFFFF:  # 32-bit
            return_value = b'\xf0' + struct.pack('!I', self.data)
        elif self.data <= 0xFFFFFFFFFFFFFFFF:  # 64-bit
            return_value = b'\xf4' + struct.pack('!Q', self.data)
        else:
            raise OverflowError('{} is too large to be encoded as a VarInt'.format(self.data))
        self.data = return_value
        return return_value

    def read_next(self):
        """
        Decodes the next integer from the VarInt data, popping the data from the array of bytes as it goes,
        so that this function can be used repeatedly on several VarInts in a row.

        Returns:
            int: the decoded integer
        """
        next_byte = self._get_next_byte()
        if next_byte >> 7 == VARINT_7_BIT:
            return_value = next_byte
        elif next_byte >> 6 == VARINT_14_BIT:
            return_value = (next_byte & 0b00111111) << 8
            return_value += self._get_next_byte()
        elif next_byte >> 5 == VARINT_21_BIT:
            return_value = (next_byte & 0b00011111) << 16
            return_value += self._get_next_byte() << 8
            return_value += self._get_next_byte()
        elif next_byte >> 4 == VARINT_28_BIT:
            return_value = (next_byte & 0b00011111) << 24
            return_value += self._get_next_byte() << 16
            return_value += self._get_next_byte() << 8
            return_value += self._get_next_byte()
        elif next_byte >> 2 == VARINT_32_BIT:
            return_value = self._get_next_byte() << 24
            return_value += self._get_next_byte() << 16
            return_value += self._get_next_byte() << 8
            return_value += self._get_next_byte()
        elif next_byte >> 2 == VARINT_64_BIT:
            return_value = self._get_next_byte() << 56
            return_value += self._get_next_byte() << 48
            return_value += self._get_next_byte() << 40
            return_value += self._get_next_byte() << 32
            return_value += self._get_next_byte() << 24
            return_value += self._get_next_byte() << 16
            return_value += self._get_next_byte() << 8
            return_value += self._get_next_byte()
        elif next_byte >> 2 == VARINT_NEGATIVE_RECURSIVE:
            varint_reader = VarInt(self.data)
            return_value = -(varint_reader.read_next())
            self.data = varint_reader.get_current_data()
        elif next_byte >> 2 == VARINT_NEGATIVE_2_BIT:
            return_value = -(next_byte & 0b00000011) - 1
        else:
            raise Exception("Invalid VarInt: " + bin(next_byte))
        return return_value

    def get_current_data(self):
        """
        Gets the VarInt-encoded data from memory.

        Returns:
            bytes: VarInt-encoded data
        """
        return bytes(self.data)
