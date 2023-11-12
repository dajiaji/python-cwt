# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Tests for COSEKey.
"""
import json

import pytest

import cwt
from cwt import Claims, COSEKey
from cwt.cose_key_interface import COSEKeyInterface

from .utils import key_path

# from secrets import token_bytes


class TestCOSEKey:
    """
    Tests for COSEKey.
    """

    def test_key_builder_constructor(self):
        c = COSEKey()
        assert isinstance(c, COSEKey)

    @pytest.mark.parametrize(
        "alg, alg_label",
        [
            ("HMAC 256/64", 4),
            ("HMAC 256/256", 5),
            ("HMAC 384/384", 6),
            ("HMAC 512/512", 7),
        ],
    )
    def test_key_builder_from_symmetric_key_hmac(self, alg, alg_label):
        k = COSEKey.from_symmetric_key("mysecret", alg=alg)
        assert isinstance(k, COSEKeyInterface)
        assert k.alg == alg_label
        assert 9 in k.key_ops
        assert 10 in k.key_ops

    @pytest.mark.parametrize(
        "alg",
        [
            "HMAC 256/64",
            "HMAC 256/256",
            "HMAC 384/384",
            "HMAC 512/512",
            "HS256",  # allow JWK alg name
            "HS384",  # allow JWK alg name
            "HS512",  # allow JWK alg name
            "A128GCM",
            "A192GCM",
            "A256GCM",
            "AES-CCM-16-64-128",
            "AES-CCM-16-64-256",
            "AES-CCM-64-64-128",
            "AES-CCM-64-64-256",
            "AES-CCM-16-128-128",
            "AES-CCM-16-128-256",
            "AES-CCM-64-128-128",
            "AES-CCM-64-128-256",
        ],
    )
    def test_key_builder_from_symmetric_key_without_key(self, alg):
        try:
            k = COSEKey.from_symmetric_key(alg=alg)
            assert k.kty == 4
        except Exception:
            pytest.fail("from_symmetric_key should not fail.")

    @pytest.mark.parametrize(
        "alg",
        ["xxx", 0, 8, 9, 34],
    )
    def test_key_builder_from_symmetric_key_with_invalid_alg(self, alg):
        with pytest.raises(ValueError) as err:
            COSEKey.from_symmetric_key("mysecret", alg=alg)
            pytest.fail("from_symmetric_key should fail.")
        assert f"Unsupported or unknown alg(3): {alg}." in str(err.value)

    @pytest.mark.parametrize(
        "key_ops",
        [["xxx"], ["MAC create", "MAC verify", "xxx"]],
    )
    def test_key_builder_from_symmetric_key_with_invalid_key_ops(self, key_ops):
        with pytest.raises(ValueError) as err:
            COSEKey.from_symmetric_key("mysecret", alg="HS256", key_ops=key_ops)
            pytest.fail("from_symmetric_key should fail.")
        assert "Unsupported or unknown key_ops." in str(err.value)

    @pytest.mark.parametrize(
        "private_key_path, public_key_path",
        [
            ("private_key_ed25519.pem", "public_key_ed25519.pem"),
            ("private_key_ed448.pem", "public_key_ed448.pem"),
            ("private_key_es256.pem", "public_key_es256.pem"),
            ("private_key_es256k.pem", "public_key_es256k.pem"),
            ("private_key_es384.pem", "public_key_es384.pem"),
            ("private_key_es512.pem", "public_key_es512.pem"),
            # ("private_key_x25519.pem", "public_key_x25519.pem"),
            # ("private_key_x448.pem", "public_key_x448.pem"),
        ],
    )
    def test_key_builder_from_pem(self, private_key_path, public_key_path):
        try:
            with open(key_path(private_key_path)) as key_file:
                COSEKey.from_pem(key_file.read())
            with open(key_path(public_key_path)) as key_file:
                COSEKey.from_pem(key_file.read())
        except Exception:
            pytest.fail("from_pem should not fail.")

    @pytest.mark.parametrize(
        "private_key_path, public_key_path",
        [
            ("private_key_x25519.pem", "public_key_x25519.pem"),
            ("private_key_x448.pem", "public_key_x448.pem"),
        ],
    )
    def test_key_builder_from_pem_with_alg(self, private_key_path, public_key_path):
        try:
            with open(key_path(private_key_path)) as key_file:
                COSEKey.from_pem(key_file.read(), alg="ECDH-SS+HKDF-256")
            with open(key_path(public_key_path)) as key_file:
                COSEKey.from_pem(key_file.read(), alg="ECDH-SS+HKDF-256")
        except Exception:
            pytest.fail("from_pem should not fail.")

    @pytest.mark.parametrize(
        "alg",
        [
            "ECDH-SS+HKDF-512",
            "ECDH-SS+HKDF-256",
            "ECDH-ES+HKDF-512",
            "ECDH-ES+HKDF-256",
            "ES256K",
            "ES512",
            "ES384",
            "ES256",
        ],
    )
    def test_key_builder_from_pem_ec2_with_alg(self, alg):
        try:
            with open(key_path("private_key_es256.pem")) as key_file:
                COSEKey.from_pem(key_file.read(), alg=alg)
        except Exception:
            pytest.fail("from_pem should not fail.")

    @pytest.mark.parametrize(
        "invalid_alg",
        [
            "HS256",
            "HS384",
            "HS512",
        ],
    )
    def test_key_builder_from_pem_ec2_with_invalid_alg(self, invalid_alg):
        with open(key_path("private_key_es256.pem")) as key_file:
            with pytest.raises(ValueError) as err:
                COSEKey.from_pem(key_file.read(), alg=invalid_alg)
                pytest.fail("from_pem() should fail.")
        assert f"Unsupported or unknown alg for EC2: {invalid_alg}." in str(err.value)

    @pytest.mark.parametrize(
        "alg",
        [
            "EdDSA",
        ],
    )
    def test_key_builder_from_pem_okp_eddsa_with_alg(self, alg):
        try:
            with open(key_path("private_key_ed25519.pem")) as key_file:
                COSEKey.from_pem(key_file.read(), alg=alg)
        except Exception:
            pytest.fail("from_pem should not fail.")

    @pytest.mark.parametrize(
        "alg",
        [
            "ECDH-SS+HKDF-512",
            "ECDH-SS+HKDF-256",
            "ECDH-ES+HKDF-512",
            "ECDH-ES+HKDF-256",
        ],
    )
    def test_key_builder_from_pem_okp_ecdhe_with_alg(self, alg):
        try:
            with open(key_path("private_key_x25519.pem")) as key_file:
                COSEKey.from_pem(key_file.read(), alg=alg)
        except Exception:
            pytest.fail("from_pem should not fail.")

    @pytest.mark.parametrize(
        "alg_id",
        [
            -25,
            -26,
            -27,
            -28,
        ],
    )
    def test_key_builder_from_pem_okp_ecdhe_with_alg_id(self, alg_id):
        try:
            with open(key_path("private_key_x25519.pem")) as key_file:
                COSEKey.from_pem(key_file.read(), alg=alg_id)
        except Exception:
            pytest.fail("from_pem should not fail.")

    @pytest.mark.parametrize(
        "invalid_alg",
        [
            "HS256",
            "HS384",
            "HS512",
        ],
    )
    def test_key_builder_from_pem_okp_with_invalid_alg(self, invalid_alg):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            with pytest.raises(ValueError) as err:
                COSEKey.from_pem(key_file.read(), alg=invalid_alg)
                pytest.fail("from_pem() should fail.")
        assert f"Unsupported or unknown alg for OKP: {invalid_alg}." in str(err.value)

    @pytest.mark.parametrize(
        "kid, expected",
        [
            (b"our-key", b"our-key"),
            ("our-key", b"our-key"),
        ],
    )
    def test_key_builder_from_pem_with_kid(self, kid, expected):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            private_key = COSEKey.from_pem(key_file.read(), kid=kid)
        with open(key_path("public_key_ed25519.pem")) as key_file:
            public_key = COSEKey.from_pem(key_file.read(), kid=kid)
        assert private_key.kid == expected
        assert public_key.kid == expected

    @pytest.mark.parametrize(
        "key_ops, expected",
        [
            ([2], [2]),
            (["verify"], [2]),
        ],
    )
    def test_key_builder_from_pem_public_with_key_ops(self, key_ops, expected):
        with open(key_path("public_key_ed25519.pem")) as key_file:
            k = COSEKey.from_pem(key_file.read(), key_ops=key_ops)
        assert len(k.key_ops) == len(key_ops)
        for ops in k.key_ops:
            assert ops in expected

    @pytest.mark.parametrize(
        "key_ops, expected",
        [
            ([1, 2], [1, 2]),
            (["sign", "verify"], [1, 2]),
            (["verify"], [2]),
            (["sign"], [1]),
        ],
    )
    def test_key_builder_from_pem_private_with_key_ops(self, key_ops, expected):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            k = COSEKey.from_pem(key_file.read(), key_ops=key_ops)
        assert len(k.key_ops) == len(key_ops)
        for ops in k.key_ops:
            assert ops in expected

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ("invalidstring", "Failed to decode PEM."),
            (b"invalidbytes", "Failed to decode PEM."),
        ],
    )
    def test_key_builder_from_pem_with_invalid_key(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            COSEKey.from_pem(invalid)
            pytest.fail("from_pem should not fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ([1], "Invalid key_ops for Ed25519/448 public key."),
            (["sign"], "Invalid key_ops for Ed25519/448 public key."),
        ],
    )
    def test_key_builder_from_pem_public_with_invalid_key_ops(self, invalid, msg):
        with open(key_path("public_key_ed25519.pem")) as key_file:
            with pytest.raises(ValueError) as err:
                COSEKey.from_pem(key_file.read(), key_ops=invalid)
                pytest.fail("from_pem should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ([9], "Unknown or not permissible key_ops(4) for OKP."),
            (
                ["MAC create"],
                "Unknown or not permissible key_ops(4) for OKP.",
            ),
            (["xxx"], "Unsupported or unknown key_ops."),
        ],
    )
    def test_key_builder_from_pem_private_with_invalid_key_ops(self, invalid, msg):
        with open(key_path("private_key_ed25519.pem")) as key_file:
            with pytest.raises(ValueError) as err:
                COSEKey.from_pem(key_file.read(), key_ops=invalid)
                pytest.fail("from_pem should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "alg, msg",
        [
            (None, "alg parameter should be specified for an RSA key."),
            ("RSxxx", "Unsupported or unknown alg: RSxxx."),
        ],
    )
    def test_key_builder_from_pem_private_with_invalid_alg(self, alg, msg):
        with open(key_path("private_key_rsa.pem")) as key_file:
            with pytest.raises(ValueError) as err:
                COSEKey.from_pem(key_file.read(), alg=alg)
                pytest.fail("from_pem should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "cose_key",
        [
            # OKP
            {
                1: 1,
                3: -8,
                -1: 6,
                -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
                -4: b"B\xc6u\xd0|-\x07\xe7)\x8d\x1c\x13\x14\xa2\x8dFC1\xdf3sQ\x049|\x14\xc1\xed\x01\xe5\xdb\xa9",
            },
            {
                1: 1,
                3: -8,
                -1: 6,
                -2: b"\x18Es\xe0\x9a\x83\xfd\x0e\xe9K\xa8n\xf39i\x17\xfe\n2+|\xd1q\xcc\x87\xd2\xe9\xa9\xe8 \x9b\xd9",
            },
            # EC2
            {
                1: 2,
                -2: b"\xa7\xddc*\xff\xc2?\x8b\xf8\x9c:\xad\xccDF\x9cZ \x04P\xef\x99\x0c=\xe6 w1\x08&\xba\xd9",
                -3: b"\xe2\xdb\xef\xfe\xb8\x8a\x12\xf27\xcb\x15:\x8a\xb9\x1a90B\x1a\x19^\xbc\xdc\xde\r\xb9s\xc1P\xf3\xaa\xdd",
                -4: b'\xe9\x16\x0c\xa96\x8d\xfa\xbc\xd5\xda"ua\xec\xf7\x96\r\x15\xf7_\xf3rb{\xb1\xde;\x99\x88\xafNh',
                -1: 1,
            },
            {
                1: 2,
                -2: b"\xa7\xddc*\xff\xc2?\x8b\xf8\x9c:\xad\xccDF\x9cZ \x04P\xef\x99\x0c=\xe6 w1\x08&\xba\xd9",
                -3: b"\xe2\xdb\xef\xfe\xb8\x8a\x12\xf27\xcb\x15:\x8a\xb9\x1a90B\x1a\x19^\xbc\xdc\xde\r\xb9s\xc1P\xf3\xaa\xdd",
                -1: 1,
            },
            # RSA
            {
                1: 3,
                3: -257,
                4: [],
                -1: b"\xcb\xd4\xc7)\xac8\xa6\xf8\xe2C_\xcaE\x96\n\xc3\xfe\x85\xa9\xef+k{\xf7\xd9\x996\x97|'`j2\xf5XuF\xaf\xfb\x06\xb1_p\xaa\xcf\x18\xbf\xc6\xb5\xa0\xc0\xb9+\x8e\xed3\x96\x81<\xc5H\x8d\xd2%\xe9\x9dM\nA\xf6\x14\xb4\xaa\xbf2\xa3f\xdb\x110\xe7\x8c\xcc\xfe\xf6>K\xf1\xcaM\xb0\xcfR\xbfa\x07\x11\x95\x18q\xb2\x81<1\xab\xfdc\x1c\xda\xe4i#\xc5\n\xec\x80\"1\xd2\x00o\xe5G\xbf^p\x17\xcd\xadj\x84\x9f\x04\x14\x94\x90I\xa8Wfu<\xe5\xdf@\xde\x8a\x04\xc6\x91\xd1S\x7fR\xa3\xf47\xdb`\xf0\x16\xa2\x0fG\xb6Au\x8b\xd7\xf8\xf0\x81\xdbI\x99\x08\x8e\x10V\xc0\xd8\xc9\xa3\x91PS\x94,\xcf\xb1e\n\xbc\x81\x18#[n\xfcH#u\x00U\xce\xd3\xcf\x97 \x81?\xa1\x8a\x88\xc4\x16\x87\xdc\xf9c#p\xa5\x18\x0eH\x92\xfd{\xd9\xb8\xc1\xdcV\xa0\xe1\xcb\x1f\xd5\x9dmR\xc2\xec\x8cB\xe7\x1e\xc3\x88\x99\xd6\xbd\xe2\xef\x17",
                -2: b"\x01\x00\x01",
                -3: b'c\xf8]"<<\xa0\xf0*\x91\x1e\xd7\'\x1f\xfa\xf1\xbb\xd0\xb4\xd2\xff\xf9\xbc\x98\x88\x19\xd4#\xa2\x19\xf1\xf8\xc4;\x7f\x02.\x04;\xdbA}l\xd5\xe9\xb2\xda\xc4K\xea\xa6\xfbj\xb8\xb3\xef\xfc^0\x7f\x16!\xb0\xb35\x8c\x17\xef\xf3\x00\r\x91\xba\xb9\x01\xce\x10\xb1[\x12 N\xf7p\t7\xee\xa9\x8d.c\x8c\x9b\xaa\x0f\x9d\x96\xeb\x08M#^\xad63\x83\x98k\xdb\x93\xf1Y@\xd8%\xbc\x86\x88\xe6\xd5\x9e\x0b\xd7\x0f\xad\xf2\xceI\nW\xbf\xeb\xb6B\x06\xc1\xe8p\xd7\xb6%;^\xe3\xce\xae:\x960\xf7(\n$e\x1b\xd1~\x7f\xb27\xf1p\x14\xde\xcf\xb3\xafu\xac\x05\x10\xee\xa1^\xf3p\x83\xf7\xddNK\x15\xb4j\x93\xc7\x01`\xd25J\xb4\x88S\x89E\xc0\x8bm\xa6\x0bV7\\\xc9\x0c`\xb5\x08\xc9\x03\x0c\xe9\xd0\xd3\xa9\xc1\x19\xbd~\x98\x83\xd6z\x18\xc1\x9d\x04\t\xc8tk\xd7U+\x1c\xc2\xc6"&\x0e5\x0bLo\xe7X\xe5**\xe3m\xf5\x83\x0c\x91',
                -4: b'\xf9c5\xd1\x00\xe4+^f\x16<G\x92\x1a\x9f\x87\xe92\xd5\x9b\x91\xb0p\xdfzW5\x00\x88{.\xff\xe5\xce\xbc\x15\xcd\x16\x7f\xda\x03\xa2\xd3\xc3\xd4C\xa9\xd3\x9d\xf2\xdc\x84\xe4\x12x&\xbb\x8c\x87ha&\xb6\x85+\xd49\xde\xc3+\xa4\xad\xa8\xb0\xd9v\xeb#s\xd8l\x1ci\xab?C\x83G#\x16{K\x7f\xae-Y9\xc9\xfe\x8f\xb7\xd4\x12\x80\xae\xc5"+y\xd1I\xed\xd0\xdc\xaeP\x07\x8b\xcc3:\xf1y\x12\xc3/\xccI',
                -5: b'\xd1<W:7*\xbbo\x96o\xfa,\x07jfD\xe2g\x08\x91I{E\xe3\xb7\x82\xa6\xc5\x06\xebE\x96\xddY\xae\x9e\x88g|\xebdrLw\xaa\xdc\xc4\x93\xda\xc2q-j\xf2y\xff\xb8\x9c\xdct\xe2\xf6\xed<"\x0e\x9aJ\x17x\x1a\xd8\xdfs@s\xcb\xf4#/\xb78\x8c\t{9\xee\x92\xae\xce\xfei\x87\x98\x12\xc1\xda\xcb\xee\x94\xa8Sm\xa0\x13m\xd7\xbd(\xf1\xac\\\xc9T\xf9\xf5j`\xf0\x97\xd5\xc7\xed\xdb\xb6\xb5 _',
                -6: b"[\xa1\xa8Ts\x0fc\x1f\xfcB\x8fC|\xdbkbt\xbc\xc8\xdf\xb0X4 \xe8\xc2\xc2&\xbf\xff\x02\xf5\xe3jb\x91`\x19\xb4@V\xb5\xad9v\xf4\xa5\xa1\xab\x97`\x8f3}\xd5\xc7\xe5\x81l\xff]2\xec=b-HV!@\x17\xf1\xf6\xd9\x84\r\xbd\xb7\xf9\x08\xbc0tc\x07\x8b\xb6\xe0\x9cs\xd69\x97`X)@\xa2\x87v'\x055\x0730\x1b\xad\xfd\xc4xuy\x18\x9c\xb3\xab\x12\"\xa5p2\xe9Y\x8b~4\x81",
                -7: b"b\x00I:\xd3,\x08\xae\xb3_\xafe\x7f\xf3\xae\x03\x05\xa8\x0c\xb3@\x1f\xa5\x14\x8b\x97~U:ph\x1f\xc9}\x7f\xf4q\x1fG\xbbYH\xcf\xd8\x1d\x07Zk\x86C\x1c\x8f\x91P\x11$]k\xdb6D83\xd5\xbe}\xe8v[\x97\xbd\xbbf\xad\xac\xba\x90\x04\xc1\x96O\xd3\x04\x84L[N\x0b\x16%\x8d\xb4\x0f\xf6\x82\x92\x99\xd0z\xe6\xd6\x10}\x80D\x99f;\x0b:f\xe8\xee\xc4\x06o\x94k\xe3D\xba\xb4\xf2\x0b\xbf\x00\x071",
                -8: b"\xdc\xb0\x1bfkH\x93\xf6X\xaa\x97\x9b\x1a\xe1\x8c{\xab\"\xe0\xa9\x9e\xf0c[\xd6-\x0f\xb1\xe0\xc0\x81\x8b\x9fO\xc7\xe8N\x98\\jw@\x0e\xe1\xd1\xa2\x1c\x0b\x8dh\x10Q\x90\x88\xef\xf3\x11\xb1\xcf\x9b)\xd8\x17;z'4\xef\x8dW\r[\x02A\xd4+\x8a\xf6\xcc\xb4\xaf\x1c\xdd?\xe4F\x10[R\x85\xa0\xe5\x1f\xd4\xdb68\xcd\xb1_\xfe\x94@$\xa0\x86\xaf\x1b\xea3\xf4\x97\x1dsd\x19,P\xc4,Eh0L\xf9J\xa9q",
            },
            {
                1: 3,
                3: -257,
                4: [],
                -1: b"\xcb\xd4\xc7)\xac8\xa6\xf8\xe2C_\xcaE\x96\n\xc3\xfe\x85\xa9\xef+k{\xf7\xd9\x996\x97|'`j2\xf5XuF\xaf\xfb\x06\xb1_p\xaa\xcf\x18\xbf\xc6\xb5\xa0\xc0\xb9+\x8e\xed3\x96\x81<\xc5H\x8d\xd2%\xe9\x9dM\nA\xf6\x14\xb4\xaa\xbf2\xa3f\xdb\x110\xe7\x8c\xcc\xfe\xf6>K\xf1\xcaM\xb0\xcfR\xbfa\x07\x11\x95\x18q\xb2\x81<1\xab\xfdc\x1c\xda\xe4i#\xc5\n\xec\x80\"1\xd2\x00o\xe5G\xbf^p\x17\xcd\xadj\x84\x9f\x04\x14\x94\x90I\xa8Wfu<\xe5\xdf@\xde\x8a\x04\xc6\x91\xd1S\x7fR\xa3\xf47\xdb`\xf0\x16\xa2\x0fG\xb6Au\x8b\xd7\xf8\xf0\x81\xdbI\x99\x08\x8e\x10V\xc0\xd8\xc9\xa3\x91PS\x94,\xcf\xb1e\n\xbc\x81\x18#[n\xfcH#u\x00U\xce\xd3\xcf\x97 \x81?\xa1\x8a\x88\xc4\x16\x87\xdc\xf9c#p\xa5\x18\x0eH\x92\xfd{\xd9\xb8\xc1\xdcV\xa0\xe1\xcb\x1f\xd5\x9dmR\xc2\xec\x8cB\xe7\x1e\xc3\x88\x99\xd6\xbd\xe2\xef\x17",
                -2: b"\x01\x00\x01",
            },
            # Symmetric
            {1: 4, 3: 1},
            {1: 4, 3: 2},
            {1: 4, 3: 3},
            {1: 4, 3: 4},
            {1: 4, 3: 5},
            {1: 4, 3: 6},
            {1: 4, 3: 7},
            {1: 4, 3: 10},
            {1: 4, 3: 11},
            {1: 4, 3: 12},
            {1: 4, 3: 13},
            {1: 4, 3: 24},
            {1: 4, 3: 30},
            {1: 4, 3: 31},
            {1: 4, 3: 32},
            {1: 4, 3: 33},
        ],
    )
    def test_key_builder_new_with_valid_args(self, cose_key):
        try:
            COSEKey.new(cose_key)
        except Exception:
            pytest.fail("new should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ({}, "kty(1) not found."),
            ({1: b"kty"}, "kty(1) should be int or str(tstr)."),
            ({1: {}}, "kty(1) should be int or str(tstr)."),
            ({1: []}, "kty(1) should be int or str(tstr)."),
            ({1: 7}, "Unsupported or unknown kty(1): 7."),
            ({1: 4, 3: b"alg"}, "alg(3) should be int or str(tstr)."),
            ({1: 4, 3: {}}, "alg(3) should be int or str(tstr)."),
            ({1: 4, 3: []}, "alg(3) should be int or str(tstr)."),
            ({1: 4, 3: 0}, "Unsupported or unknown alg(3): 0."),
        ],
    )
    def test_key_builder_new_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            COSEKey.new(invalid)
            pytest.fail("new should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "key",
        [
            "hs256.json",
            "hs384.json",
            "hs512.json",
            "private_key_ed25519.json",
            "public_key_ed25519.json",
            "private_key_ed448.json",
            "public_key_ed448.json",
            "private_key_es256.json",
            "public_key_es256.json",
            "private_key_es384.json",
            "public_key_es384.json",
            "private_key_es512.json",
            "public_key_es512.json",
            "private_key_es256k.json",
            "public_key_es256k.json",
            "private_key_rsa.json",
            "public_key_rsa.json",
        ],
    )
    def test_key_builder_from_jwk(self, key):
        try:
            with open(key_path(key)) as key_file:
                COSEKey.from_jwk(key_file.read())
        except Exception:
            pytest.fail("from_jwk should not fail.")

    def test_key_builder_from_jwk_with_byte_formatted_kid(self):
        try:
            with open(key_path("public_key_ed25519.json")) as key_file:
                obj = json.loads(key_file.read())
                obj["kid"] = b"01"
                COSEKey.from_jwk(obj)
        except Exception:
            pytest.fail("from_jwk should not fail.")

    def test_key_builder_from_jwk_with_key_ops(self):
        try:
            with open(key_path("public_key_ed25519.json")) as key_file:
                obj = json.loads(key_file.read())
                obj["key_ops"] = ["verify"]
                COSEKey.from_jwk(obj)
        except Exception:
            pytest.fail("from_jwk should not fail.")

    def test_key_builder_from_jwk_without_use(self):
        try:
            with open(key_path("public_key_ed25519.json")) as key_file:
                obj = json.loads(key_file.read())
                del obj["use"]
                COSEKey.from_jwk(obj)
        except Exception:
            pytest.fail("from_jwk should not fail.")

    @pytest.mark.parametrize(
        "private_key_path, public_key_path",
        [
            ("private_key_ed25519.json", "public_key_ed25519.json"),
            ("private_key_ed448.json", "public_key_ed448.json"),
            ("private_key_es256.json", "public_key_es256.json"),
            ("private_key_es256k.json", "public_key_es256k.json"),
            ("private_key_es384.json", "public_key_es384.json"),
            ("private_key_es512.json", "public_key_es512.json"),
            ("private_key_rsa.json", "public_key_rsa.json"),
        ],
    )
    def test_key_builder_from_jwk_with_encode_and_sign(self, private_key_path, public_key_path):
        with open(key_path(private_key_path)) as key_file:
            private_key = COSEKey.from_jwk(key_file.read())
        with open(key_path(public_key_path)) as key_file:
            public_key = COSEKey.from_jwk(key_file.read())
        token = cwt.encode_and_sign(
            Claims.from_json({"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"}),
            private_key,
        )
        # token = cwt.encode(
        #     {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"},
        #     private_key,
        # )
        decoded = cwt.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    @pytest.mark.parametrize(
        "private_key_path, public_key_path",
        [
            ("private_key_ed25519.json", "public_key_ed25519.json"),
            ("private_key_ed448.json", "public_key_ed448.json"),
            ("private_key_es256.json", "public_key_es256.json"),
            ("private_key_es256k.json", "public_key_es256k.json"),
            ("private_key_es384.json", "public_key_es384.json"),
            ("private_key_es512.json", "public_key_es512.json"),
            ("private_key_rsa.json", "public_key_rsa.json"),
        ],
    )
    def test_key_builder_from_jwk_with_encode(self, private_key_path, public_key_path):
        with open(key_path(private_key_path)) as key_file:
            private_key = COSEKey.from_jwk(key_file.read())
        with open(key_path(public_key_path)) as key_file:
            public_key = COSEKey.from_jwk(key_file.read())
        token = cwt.encode(
            {"iss": "coaps://as.example", "sub": "dajiaji", "cti": "123"},
            private_key,
        )
        decoded = cwt.decode(token, public_key)
        assert 1 in decoded and decoded[1] == "coaps://as.example"

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            ({}, "kty not found."),
            ({"kty": "xxx"}, "Unknown kty: xxx."),
            ({"kty": "OKP", "kid": 123}, "kid should be str or bytes."),
            ({"kty": "OKP", "kid": "123", "alg": 123}, "alg should be str."),
            ({"kty": "OKP", "alg": 123}, "alg should be str."),
            (
                {"kty": "OKP", "kid": "123", "alg": "xxx"},
                "Unsupported or unknown alg: xxx.",
            ),
            ({"kty": "OKP", "kid": "123"}, "crv not found."),
            ({"kty": "OKP", "kid": "123", "crv": "xxx"}, "Unknown crv: xxx."),
            (
                {"kty": "OKP", "kid": "123", "crv": "Ed25519", "use": "xxx"},
                "Unknown use: xxx.",
            ),
            (
                {"kty": "OKP", "kid": "123", "crv": "Ed25519", "key_ops": "xxx"},
                "key_ops should be list.",
            ),
            (
                {
                    "kty": "OKP",
                    "kid": "123",
                    "crv": "Ed25519",
                    "use": "enc",
                    "key_ops": ["xxx"],
                },
                "Unsupported or unknown key_ops.",
            ),
            (
                {
                    "kty": "OKP",
                    "kid": "123",
                    "crv": "Ed25519",
                    "use": "enc",
                    "key_ops": ["verify"],
                },
                "use and key_ops are conflicted each other.",
            ),
            (
                {
                    "kty": "OKP",
                    "kid": "123",
                    "crv": "Ed25519",
                    "use": "sig",
                    "key_ops": ["verify"],
                    "x5c": 123,
                },
                "x5c should be a list of str.",
            ),
            (
                {
                    "kty": "OKP",
                    "kid": "123",
                    "crv": "Ed25519",
                    "use": "sig",
                    "key_ops": ["verify"],
                    "x5c": [123],
                },
                "x5c should be a list of str.",
            ),
            # (
            #     {"kty": "oct", "kid": "123"},
            #     "k is not found or invalid format.",
            # ),
            # (
            #     {"kty": "oct", "kid": "123", "use": "sig", "key_ops": ["verify"]},
            #     "k is not found or invalid format.",
            # ),
        ],
    )
    def test_key_builder_from_jwk_with_invalid_arg(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            COSEKey.from_jwk(invalid)
            pytest.fail("from_jwk should fail.")
        assert msg in str(err.value)

    def test_cose_key_interface(self):
        ki = COSEKeyInterface({1: 4, 3: 1})
        with pytest.raises(NotImplementedError) as err:
            ki.key
            pytest.fail("key should fail.")
        assert "" == str(err.value)
        with pytest.raises(NotImplementedError) as err:
            ki.to_bytes()
            pytest.fail("to_bytes should fail.")
        assert "" == str(err.value)
        with pytest.raises(NotImplementedError) as err:
            ki.crv
            pytest.fail("crv should fail.")
        assert "" == str(err.value)
