"""
Tests for RSAKey.
"""

import pytest

from cwt.algs.rsa import RSAKey
from cwt.exceptions import EncodeError, VerifyError


@pytest.fixture(scope="session", autouse=True)
def private_key():
    return RSAKey(
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
        }
    )


@pytest.fixture(scope="session", autouse=True)
def public_key():
    return RSAKey(
        {
            1: 3,
            3: -257,
            4: [],
            -1: b"\xcb\xd4\xc7)\xac8\xa6\xf8\xe2C_\xcaE\x96\n\xc3\xfe\x85\xa9\xef+k{\xf7\xd9\x996\x97|'`j2\xf5XuF\xaf\xfb\x06\xb1_p\xaa\xcf\x18\xbf\xc6\xb5\xa0\xc0\xb9+\x8e\xed3\x96\x81<\xc5H\x8d\xd2%\xe9\x9dM\nA\xf6\x14\xb4\xaa\xbf2\xa3f\xdb\x110\xe7\x8c\xcc\xfe\xf6>K\xf1\xcaM\xb0\xcfR\xbfa\x07\x11\x95\x18q\xb2\x81<1\xab\xfdc\x1c\xda\xe4i#\xc5\n\xec\x80\"1\xd2\x00o\xe5G\xbf^p\x17\xcd\xadj\x84\x9f\x04\x14\x94\x90I\xa8Wfu<\xe5\xdf@\xde\x8a\x04\xc6\x91\xd1S\x7fR\xa3\xf47\xdb`\xf0\x16\xa2\x0fG\xb6Au\x8b\xd7\xf8\xf0\x81\xdbI\x99\x08\x8e\x10V\xc0\xd8\xc9\xa3\x91PS\x94,\xcf\xb1e\n\xbc\x81\x18#[n\xfcH#u\x00U\xce\xd3\xcf\x97 \x81?\xa1\x8a\x88\xc4\x16\x87\xdc\xf9c#p\xa5\x18\x0eH\x92\xfd{\xd9\xb8\xc1\xdcV\xa0\xe1\xcb\x1f\xd5\x9dmR\xc2\xec\x8cB\xe7\x1e\xc3\x88\x99\xd6\xbd\xe2\xef\x17",
            -2: b"\x01\x00\x01",
        }
    )


class TestRSAKey:
    """
    Tests for RSAKey.
    """

    def test_rsa_key_constructor_with_private_key(self, private_key, public_key):
        assert private_key.kty == 3
        assert private_key.kid is None
        assert private_key.alg == -257
        assert len(private_key.key_ops) == 2
        assert 1 in private_key.key_ops
        assert 2 in private_key.key_ops
        assert private_key.base_iv is None
        assert public_key.kty == 3
        assert public_key.kid is None
        assert public_key.alg == -257
        assert len(public_key.key_ops) == 1
        assert 2 in public_key.key_ops
        assert public_key.base_iv is None
        private_key_obj = private_key.to_dict()
        assert private_key_obj[1] == 3
        public_key_obj = public_key.to_dict()
        assert public_key_obj[1] == 3
        try:
            sig = private_key.sign(b"Hello world!")
            public_key.verify(b"Hello world!", sig)
        except Exception:
            pytest.fail("sign/verify should not fail.")

    @pytest.mark.parametrize(
        "invalid, msg",
        [
            (
                {1: 2},
                "kty(1) should be RSA(3).",
            ),
            (
                {1: 3},
                "alg(3) not found.",
            ),
            (
                {1: 3, 3: "xxx"},
                "Unsupported or unknown alg(3): xxx.",
            ),
            (
                {1: 3, 3: 0},
                "Unsupported or unknown alg(3) for RSA: 0.",
            ),
            (
                {1: 3, 3: -65535},
                "Unsupported or unknown alg(3) for RSA: -65535.",
            ),
            (
                {1: 3, 3: -257, 4: [3]},
                "Unknown or not permissible key_ops(4) for RSAKey: 3.",
            ),
            (
                {1: 3, 3: -257, 4: [3], -3: b"xxx"},
                "Unknown or not permissible key_ops(4) for RSAKey: 3.",
            ),
            (
                {1: 3, 3: -257, 4: [2]},
                "n(-1) should be set as bytes.",
            ),
            (
                {1: 3, 3: -257, 4: [1], -3: b"xxx"},
                "n(-1) should be set as bytes.",
            ),
            (
                {1: 3, 3: -257, 4: [1], -1: b"xxx", -3: b"xxx"},
                "e(-2) should be set as bytes.",
            ),
            (
                {1: 3, 3: -257, 4: [2], -1: b"xxx", -2: b"xxx", -4: b"xxx"},
                "RSA public key should not have private parameter: -4.",
            ),
            (
                {1: 3, 3: -257, 4: [2], -1: b"xxx", -2: b"xxx", -3: "xxx"},
                "d(-3) should be set as bytes.",
            ),
            (
                {1: 3, 3: -257, 4: [2], -1: b"xxx", -2: b"xxx", -3: b"xxx"},
                "p(-4) should be set as bytes.",
            ),
            (
                {1: 3, 3: -257, 4: [2], -1: b"xxx", -2: b"xxx", -3: b"xxx", -4: b"xxx"},
                "q(-5) should be set as bytes.",
            ),
            (
                {
                    1: 3,
                    3: -257,
                    4: [2],
                    -1: b"xxx",
                    -2: b"xxx",
                    -3: b"xxx",
                    -4: b"xxx",
                    -5: b"xxx",
                },
                "dP(-6) should be set as bytes.",
            ),
            (
                {
                    1: 3,
                    3: -257,
                    4: [2],
                    -1: b"xxx",
                    -2: b"xxx",
                    -3: b"xxx",
                    -4: b"xxx",
                    -5: b"xxx",
                    -6: b"xxx",
                },
                "dQ(-7) should be set as bytes.",
            ),
            (
                {
                    1: 3,
                    3: -257,
                    4: [2],
                    -1: b"xxx",
                    -2: b"xxx",
                    -3: b"xxx",
                    -4: b"xxx",
                    -5: b"xxx",
                    -6: b"xxx",
                    -7: b"xxx",
                },
                "qInv(-8) should be set as bytes.",
            ),
        ],
    )
    def test_rsa_key_constructor_with_invalid_args(self, invalid, msg):
        with pytest.raises(ValueError) as err:
            RSAKey(invalid)
            pytest.fail("RSAKey should fail.")
        assert msg in str(err.value)

    def test_rsa_key_sign_with_rs256_public_key(self, public_key):
        with pytest.raises(ValueError) as err:
            public_key.sign(b"Hello world!")
            pytest.fail("sign should not fail.")
        assert "Public key cannot be used for signing." in str(err.value)

    def test_rsa_key_verify_with_invalid_signature(self, private_key):
        sig = private_key.sign(b"Hello world!")
        with pytest.raises(VerifyError) as err:
            private_key.verify(b"Hello world!", sig + b"xxx")
            pytest.fail("verify should not fail.")
        assert "Failed to verify." in str(err.value)

    def test_rsa_key_constructor_with_invalid_msg(self, private_key, public_key):
        with pytest.raises(EncodeError) as err:
            private_key.sign(123)
            pytest.fail("sign should not fail.")
        assert "Failed to sign." in str(err.value)
