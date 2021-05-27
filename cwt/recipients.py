from typing import List, Optional

from .cbor_processor import CBORProcessor
from .const import COSE_ALGORITHMS_KEY_WRAP
from .cose_key import COSEKey
from .key_builder import KeyBuilder
from .recipient import Recipient
from .utils import to_cis


class Recipients(CBORProcessor):
    """
    A Set of COSE Recipients.
    """

    def __init__(self, recipients: List[Recipient]):
        self._recipients = recipients
        self._key_builder = KeyBuilder()
        return

    def derive_key(
        self,
        keys: Optional[List[COSEKey]] = None,
        materials: Optional[List[dict]] = None,
        alg_hint: int = 0,
    ) -> COSEKey:
        """
        Derive an appropriate key from recipients, keys privided as a parameter ``keys``
        or key materials as a parameter ``materials``.
        """
        if keys is not None:
            return self._derive_key_from_cose_keys(keys, alg_hint)
        if not materials:
            raise ValueError("Either keys or materials should be specified.")
        return self._derive_key_from_key_materials(materials, alg_hint)

    def _derive_key_from_cose_keys(self, keys: List[COSEKey], alg: int) -> COSEKey:
        for r in self._recipients:
            for k in keys:
                if k.kid != r.kid:
                    continue
                if r.alg == -6:  # direct
                    return k
                elif r.alg in COSE_ALGORITHMS_KEY_WRAP.values():
                    r.set_key(k.key)
                    key = r.unwrap_key()
                    kid = r.kid if isinstance(r.kid, bytes) else b""
                    return self._key_builder.from_symmetric_key(key, alg=alg, kid=kid)
        raise ValueError("Failed to derive a key.")

    def _derive_key_from_key_materials(
        self, materials: List[dict], alg: int
    ) -> COSEKey:
        for r in self._recipients:
            recipient_alg = r.alg if isinstance(r.alg, int) else 0
            for m in materials:
                if m["kid"].encode("utf-8") != r.kid:
                    continue
                ctx = to_cis(m["context"], alg, recipient_alg)
                return r.derive_key(m["value"].encode("utf-8"), context=ctx)
        raise ValueError("Failed to derive a key.")
