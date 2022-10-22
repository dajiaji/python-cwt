HPKE_KEMS = [
    0x0010,
    0x0011,
    0x0012,
    0x0020,
    0x0021,
]

HPKE_KDFS = [
    0x0001,
    0x0002,
    0x0003,
]

HPKE_AEADS = [
    0x0001,
    0x0002,
    0x0003,
]


class HPKECipherSuite:
    """
    The HPKE cipher suite which consists of KEM, KDF and AEAD.
    """

    def __init__(self, kem: int, kdf: int, aead: int):
        if kem not in HPKE_KEMS:
            raise ValueError(f"Unsupported or unknown KEM id: {kem}.")
        if kdf not in HPKE_KDFS:
            raise ValueError(f"Unsupported or unknown KDF id: {kdf}.")
        if aead not in HPKE_AEADS:
            raise ValueError(f"Unsupported or unknown AEAD id: {aead}.")
        self._kem = kem
        self._kdf = kdf
        self._aead = aead

    @property
    def kem(self) -> int:
        """
        The KEM (Key Encapsulation Mechanism) identifier.
        """
        return self._kem

    @property
    def kdf(self) -> int:
        """
        The KDF (Key Derivation Function) identifier.
        """
        return self._kdf

    @property
    def aead(self) -> int:
        """
        The AEAD (Authenticated Encryption with Additional Data) identifier.
        """
        return self._aead
