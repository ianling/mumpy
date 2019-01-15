from Crypto.Cipher import AES


AES_BLOCK_SIZE = 16  # 16 bytes == 128 bits
SHIFTBITS = 7


class MumbleCrypto:
    """
    Python implementation of the official Mumble client's custom implementation of AES-OCB.
    """
    def __init__(self, key, client_nonce, server_nonce):
        """
        Initializes a MumbleCrypto object that allows you to encrypt and decrypt data in a way that is compatible with
        the official Mumble client and server.

        Args:
            key(bytes): the encryption key
            client_nonce(bytes): the nonce to use when encrypting
            server_nonce(bytes): the nonce to use when decrypting
        """
        self.key = key
        self.client_nonce = client_nonce
        self.server_nonce = server_nonce
        self.aes = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        """
        Increments the client nonce, and then encrypts plaintext.
        Args:
            plaintext:

        Returns:
            (bytes, bytes): the tag and the ciphertext that resulted from the encryption operation
        """
        # increment nonce
        nonce = int.from_bytes(self.client_nonce, byteorder='little')
        nonce += 1
        self.client_nonce = nonce.to_bytes(AES_BLOCK_SIZE, byteorder='little')

        length_remaining = len(plaintext)
        dst = bytearray([0] * length_remaining)
        checksum = bytearray([0] * AES_BLOCK_SIZE)
        tmp = bytearray([0] * AES_BLOCK_SIZE)
        delta = self._AESencrypt(self.client_nonce)
        offset = 0

        while length_remaining > AES_BLOCK_SIZE:
            buffer = plaintext[offset:offset + AES_BLOCK_SIZE]
            MumbleCrypto._S2(delta)
            MumbleCrypto._XOR(checksum, checksum, buffer)
            MumbleCrypto._XOR(tmp, delta, buffer)
            tmp = self._AESencrypt(tmp)
            MumbleCrypto._XOR(buffer, delta, tmp)
            for i, value in enumerate(buffer):
                dst[i + offset] = value
            length_remaining -= AES_BLOCK_SIZE
            offset += AES_BLOCK_SIZE

        MumbleCrypto._S2(delta)
        MumbleCrypto._ZERO(tmp)
        num = length_remaining * 8
        tmp[AES_BLOCK_SIZE - 2] = ((num >> 8) & 0xFF)
        tmp[AES_BLOCK_SIZE - 1] = num & 0xFF
        MumbleCrypto._XOR(tmp, tmp, delta)
        pad = self._AESencrypt(tmp)
        for i, value in enumerate(plaintext[offset:offset + length_remaining]):
            tmp[i] = value
        for i, value in enumerate(pad[length_remaining:AES_BLOCK_SIZE]):
            tmp[i + length_remaining] = value
        MumbleCrypto._XOR(checksum, checksum, tmp)
        MumbleCrypto._XOR(tmp, pad, tmp)
        for i, value in enumerate(tmp[0:length_remaining]):
            dst[i + offset] = value
        MumbleCrypto._S3(delta)
        MumbleCrypto._XOR(tmp, delta, checksum)
        tag = self._AESencrypt(tmp)
        return tag, dst

    def decrypt(self, ciphertext, nonce_byte):
        """
        Syncs our stored server nonce with the nonce byte received in the packet we are decrypting,
        and then decrypts the packet.

        Args:
            ciphertext(bytes): the data to decrypt
            nonce_byte(bytes): the first byte of the nonce that the server used to encrypt the packet

        Returns:
            (bytes, bytes): the tag and the plaintext that resulted from the decryption operation
        """
        # determine correct nonce
        # TODO: If we can't determine the correct nonce, send a CryptSetup packet to resync the nonces, otherwise UDP will be broken if they ever get out of sync
        offset = 1
        nonce_byte = ord(nonce_byte)
        difference = nonce_byte - self.server_nonce[0]
        if difference != 1:
            # packets were received out of order
            if difference > 30:  # 30 seems to be arbitrary; it's used in the official client source, so I use it here
                # we wrapped around back to zero, they are still on high numbers
                offset = difference - 256
            elif difference < -30:
                # they wrapped around back to zero, we are still on high numbers
                offset = difference + 256
            elif difference == 0:
                # we either missed some multiple of exactly 255 packets, or they sent two packets with the same nonce
                # this should pretty much never happen unless the server screws up, or the network is REALLY bad
                raise ValueError("Unable to determine correct nonce to decrypt packet.")
            else:
                offset = difference

        nonce = int.from_bytes(self.server_nonce, byteorder='little')
        nonce += offset
        self.server_nonce = nonce.to_bytes(AES_BLOCK_SIZE, byteorder='little')

        ciphertext = bytearray(ciphertext)
        length_remaining = len(ciphertext)
        dst = bytearray([0] * length_remaining)
        checksum = bytearray([0] * AES_BLOCK_SIZE)
        tmp = bytearray([0] * AES_BLOCK_SIZE)
        delta = self._AESencrypt(self.server_nonce)
        offset = 0

        while length_remaining > AES_BLOCK_SIZE:
            buffer = ciphertext[offset:offset + AES_BLOCK_SIZE]
            MumbleCrypto._S2(delta)
            MumbleCrypto._XOR(tmp, delta, buffer)
            tmp = self._AESdecrypt(tmp)
            MumbleCrypto._XOR(buffer, delta, tmp)
            for i, value in enumerate(buffer):
                dst[i + offset] = value
            MumbleCrypto._XOR(checksum, checksum, buffer)
            length_remaining -= AES_BLOCK_SIZE
            offset += AES_BLOCK_SIZE

        MumbleCrypto._S2(delta)
        MumbleCrypto._ZERO(tmp)
        num = length_remaining * 8
        tmp[AES_BLOCK_SIZE - 2] = ((num >> 8) & 0xFF)
        tmp[AES_BLOCK_SIZE - 1] = num & 0xFF
        MumbleCrypto._XOR(tmp, tmp, delta)
        pad = self._AESencrypt(tmp)
        MumbleCrypto._ZERO(tmp)
        for i, value in enumerate(ciphertext[offset:offset + length_remaining]):
            tmp[i] = value
        MumbleCrypto._XOR(tmp, tmp, pad)
        MumbleCrypto._XOR(checksum, checksum, tmp)
        for i, value in enumerate(tmp[0:length_remaining]):
            dst[i + offset] = value
        MumbleCrypto._S3(delta)
        MumbleCrypto._XOR(tmp, delta, checksum)
        tag = self._AESencrypt(tmp)
        return tag, dst

    def _AESencrypt(self, plaintext):
        return bytearray(self.aes.encrypt(plaintext))

    def _AESdecrypt(self, ciphertext):
        return bytearray(self.aes.decrypt(ciphertext))

    @staticmethod
    def _XOR(dst, a, b):
        for i in range(AES_BLOCK_SIZE):
            dst[i] = a[i] ^ b[i]

    @staticmethod
    def _S2(block):
        carry = (block[0] >> SHIFTBITS) & 0x1
        for i in range(AES_BLOCK_SIZE - 1):
            block[i] = ((block[i] << 1) | ((block[i + 1] >> SHIFTBITS) & 0x1)) & 0xFF
        block[AES_BLOCK_SIZE - 1] = ((block[AES_BLOCK_SIZE - 1] << 1) ^ (carry * 0x87)) & 0xFF

    @staticmethod
    def _S3(block):
        carry = (block[0] >> SHIFTBITS) & 0x1
        for i in range(AES_BLOCK_SIZE - 1):
            block[i] ^= ((block[i] << 1) | ((block[i + 1] >> SHIFTBITS) & 0x1)) & 0xFF
        block[AES_BLOCK_SIZE - 1] ^= ((block[AES_BLOCK_SIZE - 1] << 1) ^ (carry * 0x87)) & 0xFF

    @staticmethod
    def _ZERO(block):
        for i in range(len(block)):
            block[i] = 0
