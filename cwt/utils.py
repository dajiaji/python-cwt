import base64
import copy
import json
from typing import Any, Dict, List, Optional, Union

import cbor2

from .const import (
    COSE_ALGORITHMS_CEK,
    COSE_ALGORITHMS_KEY_WRAP,
    COSE_ALGORITHMS_MAC,
    COSE_ALGORITHMS_SYMMETRIC,
    COSE_HEADER_PARAMETERS,
    COSE_KEY_LEN,
    COSE_KEY_TYPES,
    COSE_NAMED_ALGORITHMS_SUPPORTED,
    JWK_ELLIPTIC_CURVES,
    JWK_OPERATIONS,
    JWK_PARAMS_EC,
    JWK_PARAMS_OKP,
    JWK_PARAMS_RSA,
)


def i2osp(x: int, x_len: int) -> bytes:
    """
    Integer-to-Octet-String primitive
    """
    if x >= 256**x_len:
        raise ValueError("integer too large")
    digits = []
    while x:
        digits.append(int(x % 256))
        x //= 256
    for _ in range(x_len - len(digits)):
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
        x += octet_string[i] * 256**i
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


def parse_apu(context: dict) -> list:
    apu: List[Any] = [None, None, None]
    if "apu" not in context:
        return apu
    if not isinstance(context["apu"], dict):
        raise ValueError("apu should be dict.")
    if "id" in context["apu"]:
        if not isinstance(context["apu"]["id"], str):
            raise ValueError("apu.id should be str.")
        apu[0] = context["apu"]["id"].encode("utf-8")
    if "nonce" in context["apu"]:
        if isinstance(context["apu"]["nonce"], str):
            apu[1] = context["apu"]["nonce"].encode("utf-8")
        elif isinstance(context["apu"]["nonce"], int):
            apu[1] = context["apu"]["nonce"]
        else:
            raise ValueError("apu.nonce should be str or int.")
    if "other" in context["apu"]:
        if not isinstance(context["apu"]["other"], str):
            raise ValueError("apu.other should be str.")
        apu[2] = context["apu"]["other"].encode("utf-8")
    return apu


def parse_apv(context: dict) -> list:
    apv: List[Any] = [None, None, None]
    if "apv" not in context:
        return apv
    if not isinstance(context["apv"], dict):
        raise ValueError("apv should be dict.")
    if "id" in context["apv"]:
        if not isinstance(context["apv"]["id"], str):
            raise ValueError("apv.id should be str.")
        apv[0] = context["apv"]["id"].encode("utf-8")
    if "nonce" in context["apv"]:
        if isinstance(context["apv"]["nonce"], str):
            apv[1] = context["apv"]["nonce"].encode("utf-8")
        elif isinstance(context["apv"]["nonce"], int):
            apv[1] = context["apv"]["nonce"]
        else:
            raise ValueError("apv.nonce should be str or int.")
    if "other" in context["apv"]:
        if not isinstance(context["apv"]["other"], str):
            raise ValueError("apv.other should be str.")
        apv[2] = context["apv"]["other"].encode("utf-8")
    return apv


def to_cis(context: Dict[str, Any], recipient_alg: Optional[int] = None) -> List[Any]:
    res: List[Any] = []

    # AlgorithmID
    if "alg" not in context:
        raise ValueError("alg not found.")
    # if context["alg"] not in COSE_NAMED_ALGORITHMS_SUPPORTED:
    if (
        context["alg"] not in COSE_ALGORITHMS_CEK
        and context["alg"] not in COSE_ALGORITHMS_MAC
        and context["alg"] not in COSE_ALGORITHMS_KEY_WRAP
    ):
        raise ValueError(f'Unsupported or unknown alg for context information: {context["alg"]}.')
    alg = COSE_NAMED_ALGORITHMS_SUPPORTED[context["alg"]]
    res.append(alg)

    # PartyU
    res.append(parse_apu(context))

    # PartyV
    res.append(parse_apv(context))

    # SuppPubInfo
    supp_pub: List[Any] = [None, None]
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
            protected = to_cose_header(copy.deepcopy(context["supp_pub"]["protected"]))
            supp_pub[1] = cbor2.dumps(protected)
        if "other" in context["supp_pub"]:
            if not isinstance(context["supp_pub"]["other"], str):
                raise ValueError("supp_pub.other should be str.")
            supp_pub.append(context["supp_pub"]["other"].encode("utf-8"))
    supp_pub[0] = COSE_KEY_LEN[alg]
    if recipient_alg:
        protected[1] = recipient_alg
        supp_pub[1] = cbor2.dumps(protected)
    res.append(supp_pub)

    # TODO SuppPrivInfo
    return res


def to_cose_header(data: Optional[dict] = None, algs: Dict[str, int] = {}) -> Dict[int, Any]:
    if data is None:
        return {}
    if len(data) == 0:
        return {}
    res: Dict[int, Any] = {}
    # If there are no string keys, assume already numeric COSE header map
    has_str_key = any(isinstance(k, str) for k in data.keys())
    if not has_str_key:
        return data
    if not algs:
        algs = COSE_NAMED_ALGORITHMS_SUPPORTED
    for k, v in data.items():
        if isinstance(k, str):
            if k not in COSE_HEADER_PARAMETERS.keys():
                raise ValueError(f"Unsupported or unknown COSE header parameter: {k}.")
            if k == "alg":
                if v not in algs.keys():
                    raise ValueError(f"Unsupported or unknown alg: {v}.")
                v = algs[v]
            else:
                v = v.encode("utf-8") if isinstance(v, str) else v
                if k == "salt":
                    if not isinstance(v, bytes):
                        raise ValueError("salt should be bytes or str.")
                if k == "ek":
                    if not isinstance(v, (bytes, bytearray)):
                        raise ValueError("ek (-4) must be bstr.")
                if k == "psk_id":
                    if not isinstance(v, (bytes, bytearray)):
                        raise ValueError("psk_id (-5) must be bstr.")
            res[COSE_HEADER_PARAMETERS[k]] = v
        else:
            # keep numeric keys as-is
            res[k] = v
    return res


def jwk_to_cose_key_params(data: Union[str, bytes, Dict[str, Any]]) -> Dict[int, Any]:
    cose_key: Dict[int, Any] = {}

    # kty
    jwk: Dict[str, Any]
    if not isinstance(data, dict):
        jwk = json.loads(data)
    else:
        jwk = data
    if "kty" not in jwk:
        raise ValueError("kty not found.")
    if jwk["kty"] not in COSE_KEY_TYPES:
        raise ValueError(f"Unknown kty: {jwk['kty']}.")
    cose_key[1] = COSE_KEY_TYPES[jwk["kty"]]

    # kid
    if "kid" in jwk:
        if not isinstance(jwk["kid"], (str, bytes)):
            raise ValueError("kid should be str or bytes.")
        if isinstance(jwk["kid"], str):
            cose_key[2] = jwk["kid"].encode("utf-8")
        else:
            cose_key[2] = jwk["kid"]

    # alg
    if "alg" in jwk:
        if not isinstance(jwk["alg"], str):
            raise ValueError("alg should be str.")
        if jwk["alg"] not in COSE_NAMED_ALGORITHMS_SUPPORTED:
            raise ValueError(f"Unsupported or unknown alg: {jwk['alg']}.")
        cose_key[3] = COSE_NAMED_ALGORITHMS_SUPPORTED[jwk["alg"]]

    # key operation dependent conversion
    is_public = False
    if cose_key[1] == 4:  # Symmetric
        if "k" in jwk:
            if not isinstance(jwk["k"], str):
                raise ValueError("k should be str.")
            cose_key[-1] = base64url_decode(jwk["k"])
    elif cose_key[1] == 3:  # RSA
        for k, v in jwk.items():
            if k not in JWK_PARAMS_RSA:
                continue
            cose_key[JWK_PARAMS_RSA[k]] = base64url_decode(v)
        if -3 not in cose_key:
            is_public = True

    else:  # OKP/EC2
        if "crv" not in jwk:
            raise ValueError("crv not found.")
        if jwk["crv"] not in JWK_ELLIPTIC_CURVES:
            raise ValueError(f"Unknown crv: {jwk['crv']}.")
        cose_key[-1] = JWK_ELLIPTIC_CURVES[jwk["crv"]]

        if cose_key[1] == 1:  # OKP
            for k, v in jwk.items():
                if k not in JWK_PARAMS_OKP:
                    continue
                cose_key[JWK_PARAMS_OKP[k]] = base64url_decode(v)

        else:  # EC2
            for k, v in jwk.items():
                if k not in JWK_PARAMS_EC:
                    continue
                cose_key[JWK_PARAMS_EC[k]] = base64url_decode(v)
        if -4 not in cose_key:
            is_public = True

    # use/key_ops
    use = 0
    if "use" in jwk:
        if jwk["use"] == "enc":
            use = 4 if is_public else 3  # 3: encrypt, 4: decrypt
        elif jwk["use"] == "sig":
            if cose_key[1] == 4:
                use = 10  # 10: MAC verify
            else:
                use = 2 if is_public else 1  # 1: sign, 2: verify
        else:
            raise ValueError(f"Unknown use: {jwk['use']}.")
    if "key_ops" in jwk:
        if not isinstance(jwk["key_ops"], list):
            raise ValueError("key_ops should be list.")
        cose_key[4] = []
        try:
            for ops in jwk["key_ops"]:
                cose_key[4].append(JWK_OPERATIONS[ops])
        except KeyError as err:
            raise ValueError("Unsupported or unknown key_ops.") from err
        if use != 0 and use not in cose_key[4]:
            raise ValueError("use and key_ops are conflicted each other.")
    else:
        if use != 0:
            cose_key[4] = []
            cose_key[4].append(use)
    if "x5c" in jwk:
        if not isinstance(jwk["x5c"], list):
            raise ValueError("x5c should be a list of str.")
        cose_key[33] = []
        for v in jwk["x5c"]:
            if not isinstance(v, str):
                raise ValueError("x5c should be a list of str.")
            cose_key[33].append(base64url_decode(v))
    return cose_key


def _validate_context(context: List[Any]) -> List[Any]:
    if len(context) != 4 and len(context) != 5:
        raise ValueError("Invalid context information.")
    # AlgorithmID
    if not isinstance(context[0], int):
        raise ValueError("AlgorithmID should be int.")
    if context[0] not in COSE_ALGORITHMS_SYMMETRIC.values():
        raise ValueError(f"Unsupported or unknown algorithm: {context[0]}.")
    # PartyVInfo
    if not isinstance(context[1], list) or len(context[1]) != 3:
        raise ValueError("PartyUInfo should be list(size=3).")
    # PartyUInfo
    if not isinstance(context[2], list) or len(context[2]) != 3:
        raise ValueError("PartyVInfo should be list(size=3).")
    # SuppPubInfo
    if not isinstance(context[3], list) or (len(context[3]) != 2 and len(context[3]) != 3):
        raise ValueError("SuppPubInfo should be list(size=2 or 3).")
    return context


def to_recipient_context(alg: int, u: Dict[int, Any], context: Union[List[Any], Dict[str, Any]]) -> List[Any]:
    ctx: List[Any] = [
        None,
        [
            u[-21] if -21 in u else None,
            u[-22] if -22 in u else None,
            u[-23] if -23 in u else None,
        ],
        [
            u[-24] if -24 in u else None,
            u[-25] if -25 in u else None,
            u[-26] if -26 in u else None,
        ],
        [None, None],
    ]
    supplied_ctx = to_cis(context, alg) if isinstance(context, dict) else _validate_context(context)
    for i, item in enumerate(supplied_ctx):
        if i == 0:
            ctx[0] = item
            continue
        for j, v in enumerate(item):
            if not v:
                continue
            if i != 3 or j != 2:
                ctx[i][j] = v
            else:
                ctx[i].append(v)
    return ctx


def sort_keys_for_deterministic_encoding(d: Dict[int, Any]) -> Dict[int, Any]:
    return {k: v for k, v in sorted(d.items(), key=lambda kv: cbor2.dumps(kv[0]))}
