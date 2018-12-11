import struct
import opuslib


VARINT_7_BIT = 0b0
VARINT_14_BIT = 0b10
VARINT_21_BIT = 0b110
VARINT_28_BIT = 0b1110
VARINT_32_BIT = 0b111100
VARINT_64_BIT = 0b111101
VARINT_NEGATIVE_RECURSIVE = 0b111110
VARINT_NEGATIVE_2_BIT = 0b111111


class VarInt():
    def __init__(self, data):
        self.data = data


    def _get_next_byte(self):
        next_byte = struct.unpack('!B', self.data[:1])[0]
        self.data = self.data[1:]
        return next_byte


    def read_next(self):
        next_byte = self._get_next_byte()
        if next_byte >> 7 == VARINT_7_BIT:
            return next_byte
        elif next_byte >> 6 == VARINT_14_BIT:
            return_value = (next_byte & 0b00111111) << 8
            return_value += self._get_next_byte()
            return return_value
        elif next_byte >> 5 == VARINT_21_BIT:
            return_value = (next_byte & 0b00011111) << 16
            return_value += self._get_next_byte() << 8
            return_value += self._get_next_byte()
            return return_value
        elif next_byte >> 4 == VARINT_28_BIT:
            print('28 bit')
            return_value = (next_byte & 0b00011111) << 24
            return_value += self._get_next_byte() << 16
            return_value += self._get_next_byte() << 8
            return_value += self._get_next_byte()
            return return_value
        elif next_byte >> 2 == VARINT_32_BIT:
            return_value = self._get_next_byte() << 24
            return_value += self._get_next_byte() << 16
            return_value += self._get_next_byte() << 8
            return_value += self._get_next_byte()
            return return_value
        elif next_byte >> 2 == VARINT_64_BIT:
            return_value = self._get_next_byte() << 56
            return_value += self._get_next_byte() << 48
            return_value += self._get_next_byte() << 40
            return_value += self._get_next_byte() << 32
            return_value += self._get_next_byte() << 24
            return_value += self._get_next_byte() << 16
            return_value += self._get_next_byte() << 8
            return_value += self._get_next_byte()
            return return_value
        elif next_byte >> 2 == VARINT_NEGATIVE_RECURSIVE:
            varint_reader = VarInt(self.data)
            return_value = varint_reader.read_next()
            self.data = varint_reader.get_current_data()
            return -(return_value)
        elif next_byte >> 2 == VARINT_NEGATIVE_2_BIT:
            return_value = -(next_byte & 0b00000011) - 1
            return return_value
        else:
            raise Exception("Invalid VarInt: " + bin(next_byte))


    def get_current_data(self):
        return self.data

a = VarInt(b'\xe0\x8f\xff\xff')
print(a.read_next())
