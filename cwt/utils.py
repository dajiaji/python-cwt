import base64
from typing import Any, Dict, List, Optional

import cbor2

from .const import COSE_HEADER_PARAMETERS, COSE_KEY_LEN, COSE_NAMED_ALGORITHMS_SUPPORTED


def i2osp(x: int, x_len: int) -> bytes:
    """
    Integer-to-Octet-String primitive
    """
    if x >= 256 ** x_len:
        raise ValueError("integer too large")
    digits = []
    while x:
        digits.append(int(x % 256))
        x //= 256
    for i in range(x_len - len(digits)):
        digits.append(0)
    return bytes.fromhex("".join("%.2x" % x for x in digits[::-1]))


def os2ip(octet_string: bytes) -> int:
    """
    Octet-String-to-Integer primitive
    """
    x_len = len(octet_string)
    octet_string = octet_string[::-1]
    x = 0
    for i in range(x_len):
        x += octet_string[i] * 256 ** i
    return x


def uint_to_bytes(v: int) -> bytes:
    if v < 0:
        raise ValueError("Not a positive number.")
    rem = v
    length = 0
    while rem != 0:
        rem = rem >> 8
        length += 1
    return v.to_bytes(length, "big")


def base64url_decode(v: str) -> bytes:
    bv = v.encode("ascii")
    rem = len(bv) % 4
    if rem > 0:
        bv += b"=" * (4 - rem)
    return base64.urlsafe_b64decode(bv)


def to_cis(context: Dict[str, Any], alg: int = 0, recipient_alg: int = 0) -> List[Any]:
    res: List[Any] = []

    if alg == 0:
        if "alg" not in context:
            raise ValueError("alg not found.")
        if context["alg"] not in COSE_NAMED_ALGORITHMS_SUPPORTED:
            raise ValueError(f'Unsupported or unknown alg: {context["alg"]}.')
        alg = COSE_NAMED_ALGORITHMS_SUPPORTED[context["alg"]]
    res.append(alg)

    # PartyU
    party_u: List[Any] = [None, None, None]
    if "party_u" in context:
        if not isinstance(context["party_u"], dict):
            raise ValueError("party_u should be dict.")
        if "identity" in context["party_u"]:
            if not isinstance(context["party_u"]["identity"], str):
                raise ValueError("party_u.identity should be str.")
            party_u[0] = context["party_u"]["identity"].encode("utf-8")
        if "nonce" in context["party_u"]:
            if isinstance(context["party_u"]["nonce"], str):
                party_u[1] = context["party_u"]["nonce"].encode("utf-8")
            elif isinstance(context["party_u"]["nonce"], int):
                party_u[1] = context["party_u"]["nonce"]
            else:
                raise ValueError("party_u.nonce should be str or int.")
        if "other" in context["party_u"]:
            if not isinstance(context["party_u"]["other"], str):
                raise ValueError("party_u.other should be str.")
            party_u[2] = context["party_u"]["other"].encode("utf-8")
    res.append(party_u)

    # PartyV
    party_v: List[Any] = [None, None, None]
    if "party_v" in context:
        if not isinstance(context["party_v"], dict):
            raise ValueError("party_v should be dict.")
        if "identity" in context["party_v"]:
            if not isinstance(context["party_v"]["identity"], str):
                raise ValueError("party_v.identity should be str.")
            party_v[0] = context["party_v"]["identity"].encode("utf-8")
        if "nonce" in context["party_v"]:
            if isinstance(context["party_v"]["nonce"], str):
                party_v[1] = context["party_v"]["nonce"].encode("utf-8")
            elif isinstance(context["party_v"]["nonce"], int):
                party_v[1] = context["party_v"]["nonce"]
            else:
                raise ValueError("party_v.nonce should be str or int.")
        if "other" in context["party_v"]:
            if not isinstance(context["party_v"]["other"], str):
                raise ValueError("party_v.other should be str.")
            party_v[2] = context["party_v"]["other"].encode("utf-8")
    res.append(party_v)

    # SuppPubInfo
    supp_pub: List[Any] = [None, None, None]
    protected = {}
    if "supp_pub" in context:
        if not isinstance(context["supp_pub"], dict):
            raise ValueError("supp_pub should be dict.")
        if "key_data_length" in context["supp_pub"]:
            if not isinstance(context["supp_pub"]["key_data_length"], int):
                raise ValueError("supp_pub.key_data_length should be int.")
            supp_pub[0] = context["supp_pub"]["key_data_length"]
        if "protected" in context["supp_pub"]:
            if not isinstance(context["supp_pub"]["protected"], dict):
                raise ValueError("supp_pub.protected should be dict.")
            protected = context["supp_pub"]["protected"]
            supp_pub[1] = cbor2.dumps(protected)

        if "other" in context["supp_pub"]:
            if not isinstance(context["supp_pub"]["other"], str):
                raise ValueError("supp_pub.other should be str.")
            supp_pub[2] = context["supp_pub"]["other"].encode("utf-8")
    if alg not in COSE_KEY_LEN:
        raise ValueError(f"Unsupported or unknown alg: {alg}.")
    supp_pub[0] = COSE_KEY_LEN[alg]
    if recipient_alg != 0:
        protected[1] = recipient_alg
        supp_pub[1] = cbor2.dumps(protected)
    res.append(supp_pub)

    # TODO SuppPrivInfo
    return res


def to_cose_header(
    data: Optional[dict] = None, algs: Dict[str, int] = {}
) -> Dict[int, Any]:
    if data is None:
        return {}
    res: Dict[int, Any] = {}
    if len(data) == 0 or not isinstance(list(data.keys())[0], str):
        return data
    if not algs:
        algs = COSE_NAMED_ALGORITHMS_SUPPORTED
    for k, v in data.items():
        if k not in COSE_HEADER_PARAMETERS.keys():
            raise ValueError(f"Unsupported or unknown COSE header parameter: {k}.")
        if k == "alg":
            if v not in algs.keys():
                raise ValueError(f"Unsupported or unknown alg: {v}.")
            v = algs[v]
        else:
            v = v.encode("utf-8") if isinstance(v, str) else v
        res[COSE_HEADER_PARAMETERS[k]] = v
    return res
