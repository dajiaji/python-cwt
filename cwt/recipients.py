from typing import Any, Dict, List, Optional, Union

from .cbor_processor import CBORProcessor
from .cose_key import COSEKey
from .cose_key_interface import COSEKeyInterface
from .recipient import Recipient
from .recipient_interface import RecipientInterface


class Recipients(CBORProcessor):
    """
    A Set of COSE Recipients.
    """

    def __init__(self, recipients: List[RecipientInterface], verify_kid: bool = False):
        self._recipients = recipients
        self._verify_kid = verify_kid
        return

    @classmethod
    def from_list(
        cls,
        recipients: List[Any],
        verify_kid: bool = False,
        context: Optional[Union[List[Any], Dict[str, Any]]] = None,
    ):
        """
        Create Recipients from a CBOR-like list.
        """
        res: List[RecipientInterface] = []
        for r in recipients:
            res.append(Recipient.from_list(r, context))
        return cls(res, verify_kid)

    def derive_key(self, keys: List[COSEKeyInterface], alg: int, external_aad: bytes, content_aad: bytes) -> COSEKeyInterface:
        """
        Decodes an appropriate key from recipients or keys provided as a parameter ``keys``.
        """
        if not self._recipients:
            raise ValueError("No recipients.")
        err: Exception = ValueError("key is not found.")
        for r in self._recipients:
            if not r.kid and self._verify_kid:
                raise ValueError("kid should be specified in recipient.")
            aad = self._dumps([content_aad, r.b_protected, external_aad])
            if r.kid:
                for k in keys:
                    if k.kid != r.kid:
                        continue
                    try:
                        res = r.decode(k, aad, alg=alg, as_cose_key=True)
                        if not isinstance(res, COSEKeyInterface):
                            raise TypeError("Internal type error.")
                        return res
                    except Exception as e:
                        err = e
                continue
            for k in keys:
                try:
                    res = r.decode(k, aad, alg=alg, as_cose_key=True)
                    if not isinstance(res, COSEKeyInterface):
                        raise TypeError("Internal type error.")
                    return res
                except Exception as e:
                    err = e
        raise err

    def _create_key(self, alg: int, k: COSEKeyInterface, r: RecipientInterface) -> COSEKeyInterface:
        if r.alg == -6:  # direct
            # if k.alg != alg:
            #     raise ValueError("alg mismatch.")
            return k
        return COSEKey.new({1: 4, 3: alg, -1: r.decode(k)})
