import json
import os
import zlib
from typing import Any, Dict, Union

import jwt
import requests
from base45 import b45decode

import cwt
from cwt import COSEKey


class SwedishVerifier:
    def __init__(self, base_url: str, trustlist_store_path: str):
        self._base_url = base_url
        self._trustlist_store_path = trustlist_store_path
        self._dscs: list = []
        self._trustlist: list = []
        self._load_trustlist()

    @classmethod
    def new(cls, base_url: str, trustlist_store_path: str):
        return cls(base_url, trustlist_store_path)

    def refresh_trustlist(self):
        self._dscs = []
        self._trustlist = []

        # Get a trust-list signer certificate.
        r = requests.get(self._base_url + "/cert")
        if r.status_code != 200:
            raise Exception(f"Received {r.status_code} from /cert")
        key = r.text
        cose_key = COSEKey.from_pem(key)

        # Get DSCs
        r = requests.get(self._base_url + "/trust-list")
        if r.status_code != 200:
            raise Exception(f"Received {r.status_code} from /trust-list")
        decoded = jwt.decode(
            r.text,
            cose_key.key,
            algorithms=["ES256"],
            options={"verify_aud": False},
        )
        for v in decoded["dsc_trust_list"].values():
            for k in v["keys"]:
                if "use" in k and k["use"] == "enc":
                    # Workaround for Swedish DSC.
                    del k["use"]
                if k["kty"] == "RSA":
                    k["alg"] = "PS256"
                self._dscs.append(COSEKey.from_jwk(k))
            self._trustlist.append(k)

        # Update trustlist store.
        with open(self._trustlist_store_path, "w") as f:
            json.dump(self._trustlist, f, indent=4)
        return

    def verify_and_decode(self, eudcc: bytes) -> Union[Dict[int, Any], bytes]:
        if eudcc.startswith(b"HC1:"):
            # Decode Base45 data.
            eudcc = b45decode(eudcc[4:])
            # Decompress with zlib.
            eudcc = zlib.decompress(eudcc)
        # Verify and decode CWT.
        return cwt.decode(eudcc, keys=self._dscs)

    def _load_trustlist(self):
        try:
            with open(self._trustlist_store_path) as f:
                self._trustlist = json.load(f)
            self._dscs = [COSEKey.from_jwk(k) for k in self._trustlist]
        except Exception as err:
            if type(err) is not FileNotFoundError:
                raise err
            self._trustlist = []
        return


# An endpoint of Digital Green Certificate Verifier Service compliant with:
# https://github.com/DIGGSweden/dgc-trust/blob/main/specifications/trust-list.md
BASE_URL = os.environ["CWT_SAMPLES_EUDCC_BASE_URL"]

# e.g., "./dscs.json"
TRUSTLIST_STORE_PATH = os.environ["CWT_SAMPLES_EUDCC_TRUSTLIST_STORE_PATH"]

# quoted from https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/AT/2DCode/raw/1.json
BASE45_FORMATTED_EUDCC = b"HC1:NCFOXN%TS3DH3ZSUZK+.V0ETD%65NL-AH-R6IOOK.IR9B+9G4G50PHZF0AT4V22F/8X*G3M9JUPY0BX/KR96R/S09T./0LWTKD33236J3TA3M*4VV2 73-E3GG396B-43O058YIB73A*G3W19UEBY5:PI0EGSP4*2DN43U*0CEBQ/GXQFY73CIBC:G 7376BXBJBAJ UNFMJCRN0H3PQN*E33H3OA70M3FMJIJN523.K5QZ4A+2XEN QT QTHC31M3+E32R44$28A9H0D3ZCL4JMYAZ+S-A5$XKX6T2YC 35H/ITX8GL2-LH/CJTK96L6SR9MU9RFGJA6Q3QR$P2OIC0JVLA8J3ET3:H3A+2+33U SAAUOT3TPTO4UBZIC0JKQTL*QDKBO.AI9BVYTOCFOPS4IJCOT0$89NT2V457U8+9W2KQ-7LF9-DF07U$B97JJ1D7WKP/HLIJL8JF8JFHJP7NVDEBU1J*Z222E.GJ457661CFFTWM-8P2IUE7K*SSW613:9/:TT5IYQBTBU16R4I1A/9VRPJ-TS.7ZEM7MSVOCD4RG2L-TQJROXL2J:52J7F0Q10SMAP3CG3KHF0DWIH"
# RAW_EUDCC = bytes.fromhex(
#     "d2844da20448d919375fc1e7b6b20126a0590133a4041a61817ca0061a60942ea001624154390103a101a4617681aa62646e01626d616d4f52472d3130303033303231356276706a313131393334393030376264746a323032312d30322d313862636f624154626369783155524e3a555643493a30313a41543a31303830373834334639344145453045453530393346424332353442443831332342626d706c45552f312f32302f31353238626973781b4d696e6973747279206f66204865616c74682c20417573747269616273640262746769383430353339303036636e616da463666e74754d5553544552465241553c474f455353494e47455262666e754d7573746572667261752d47c3b6c39f696e67657263676e74684741425249454c4562676e684761627269656c656376657265312e302e3063646f626a313939382d30322d323658405812fce67cb84c3911d78e3f61f890d0c80eb9675806aebed66aa2d0d0c91d1fc98d7bcb80bf00e181806a9502e11b071325901bd0d2c1b6438747b8cc50f521"
# )

if __name__ == "__main__":
    v = SwedishVerifier.new(BASE_URL, TRUSTLIST_STORE_PATH)
    v.refresh_trustlist()
    try:
        res = v.verify_and_decode(BASE45_FORMATTED_EUDCC)  # or RAW_EUDCC
    except Exception as err:
        print("Verification failed: %s" % err)
        exit(1)
    hcert = res[-260]
    print(hcert)
    exit(0)
