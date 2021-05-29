from typing import Any, Dict

from ..const import COSE_KEY_OPERATION_VALUES
from ..cose_key_interface import COSEKeyInterface


class SignatureKey(COSEKeyInterface):
    _ACCEPTABLE_PUBLIC_KEY_OPS = [
        COSE_KEY_OPERATION_VALUES["verify"],
    ]

    _ACCEPTABLE_PRIVATE_KEY_OPS = [
        COSE_KEY_OPERATION_VALUES["sign"],
        COSE_KEY_OPERATION_VALUES["verify"],
    ]

    def __init__(self, cose_key: Dict[int, Any]):
        super().__init__(cose_key)

        # Validate key_opt.
        if -4 not in cose_key:
            if not self._key_ops:
                self._key_ops = SignatureKey._ACCEPTABLE_PUBLIC_KEY_OPS
                return
            not_acceptable = [
                ops
                for ops in self._key_ops
                if ops not in SignatureKey._ACCEPTABLE_PUBLIC_KEY_OPS
            ]
            if not_acceptable:
                raise ValueError(
                    f"Unknown or not permissible key_ops(4) for SignatureKey: {not_acceptable[0]}."
                )
            return
        if not self._key_ops:
            self._key_ops = SignatureKey._ACCEPTABLE_PRIVATE_KEY_OPS
            return
        not_acceptable = [
            ops
            for ops in self._key_ops
            if ops not in SignatureKey._ACCEPTABLE_PRIVATE_KEY_OPS
        ]
        if not_acceptable:
            raise ValueError(
                f"Unknown or not permissible key_ops(4) for SignatureKey: {not_acceptable[0]}."
            )
        return
