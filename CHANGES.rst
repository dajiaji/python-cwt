Changes
=======

Unreleased
----------

Version 1.5.7
-------------

Released 2022-10-08

- Update dependencies.
    - Bump cryptography to 38.0.1. `#248 <https://github.com/dajiaji/python-cwt/pull/248>`__
- Update dev dependencies.
    - Bump pre-commit/mirrors-mypy to 0.981. `#254 <https://github.com/dajiaji/python-cwt/pull/254>`__
    - Bump sphinx to 5.2.3. `#253 <https://github.com/dajiaji/python-cwt/pull/253>`__
    - Bump pytest-cov to 4.0.0. `#252 <https://github.com/dajiaji/python-cwt/pull/252>`__
    - Bump tox to 3.26.0. `#249 <https://github.com/dajiaji/python-cwt/pull/249>`__
    - Bump pre-commit/black to 22.8.0. `#246 <https://github.com/dajiaji/python-cwt/pull/246>`__

Version 1.5.6
-------------

Released 2022-08-10

- Update dependencies.
    - Bump cryptography to 37.0.4. `#239 <https://github.com/dajiaji/python-cwt/pull/239>`__
- Update dev dependencies.
    - Bump pre-commit/flake8 to 5.0.4. `#244 <https://github.com/dajiaji/python-cwt/pull/244>`__
    - Bump sphinx to 5.1.1. `#242 <https://github.com/dajiaji/python-cwt/pull/242>`__
    - Bump pre-commit/mirrors-mypy to 0.971. `#240 <https://github.com/dajiaji/python-cwt/pull/240>`__
    - Bump pre-commit/black to 22.6.0. `#238 <https://github.com/dajiaji/python-cwt/pull/238>`__
    - Bump tox to 3.25.1. `#237 <https://github.com/dajiaji/python-cwt/pull/237>`__
- Drop support for Python3.6. `#236 <https://github.com/dajiaji/python-cwt/pull/236>`__

Version 1.5.5
-------------

Released 2022-06-18

- Update dependencies.
    - Bump cryptography to 37.0.2 `#228 <https://github.com/dajiaji/python-cwt/pull/228>`__
- Update dev dependencies.
    - Bump sphinx to 5.0.2. `#233 <https://github.com/dajiaji/python-cwt/pull/233>`__
    - Bump pre-commit/mirrors-mypy to 0.961. `#232 <https://github.com/dajiaji/python-cwt/pull/232>`__
    - Bump pre-commit/pre-commit-hooks to 4.3.0. `#232 <https://github.com/dajiaji/python-cwt/pull/232>`__
    - Bump tox to 3.25.0. `#224 <https://github.com/dajiaji/python-cwt/pull/224>`__

Version 1.5.4
-------------

Released 2022-04-03

- Update dependencies.
    - Bump asn1crypto from 1.4.0 to 1.5.1. `#218 <https://github.com/dajiaji/python-cwt/pull/218>`__
    - Bump cryptography from 36.0.1 to 36.0.2. `#217 <https://github.com/dajiaji/python-cwt/pull/217>`__
    - Bump cbor2 from 5.4.2 to 5.4.2.post1. `#211 <https://github.com/dajiaji/python-cwt/pull/211>`__
- Update dev dependencies.
    - Bump pre-commit/mirrors-mypy from 0.930 to 0.942. `#221 <https://github.com/dajiaji/python-cwt/pull/221>`__
    - Bump sphinx from 4.3.2 to 4.5.0. `#220 <https://github.com/dajiaji/python-cwt/pull/220>`__
    - Bump pytest from 6.2.5 to 7.0.1. `#213 <https://github.com/dajiaji/python-cwt/pull/213>`__
- Add pre-commit hooks for checking json, toml and yaml files. `#207 <https://github.com/dajiaji/python-cwt/pull/208>`__
- Migrate mypy to pre-commit. `#206 <https://github.com/dajiaji/python-cwt/pull/206>`__

Version 1.5.3
-------------

Released 2022-01-01

- Add 2022 to copyright and license. `#205 <https://github.com/dajiaji/python-cwt/pull/205>`__
- Fix link to homepage on PyPI. `#204 <https://github.com/dajiaji/python-cwt/pull/204>`__
- Add license information to PyPI. `#204 <https://github.com/dajiaji/python-cwt/pull/204>`__

Version 1.5.2
-------------

Released 2021-12-31

- Refine github action. `#202 <https://github.com/dajiaji/python-cwt/pull/202>`__
- Refine tox.ini. `#202 <https://github.com/dajiaji/python-cwt/pull/202>`__
- Use pytest-cov instead of coverage. `#202 <https://github.com/dajiaji/python-cwt/pull/202>`__
- Refine pyproject.toml. `#202 <https://github.com/dajiaji/python-cwt/pull/202>`__
- Add poetry.lock. `#202 <https://github.com/dajiaji/python-cwt/pull/202>`__

Version 1.5.1
-------------

Released 2021-12-15

- Use the default salt length for PS256/384/512 instead of the max length. `#195 <https://github.com/dajiaji/python-cwt/pull/195>`__

Version 1.5.0
-------------

Released 2021-12-11

- Migrate to poetry. `#191 <https://github.com/dajiaji/python-cwt/pull/191>`__
- Change max line length to 128. `#191 <https://github.com/dajiaji/python-cwt/pull/191>`__
- Fix updated flake8 warning. `#191 <https://github.com/dajiaji/python-cwt/pull/191>`__

Version 1.4.2
-------------

Released 2021-10-16

- Add support for Python 3.10. `#183 <https://github.com/dajiaji/python-cwt/pull/183>`__

Version 1.4.1
-------------

Released 2021-10-11

- Make public types explicit for PyLance. `#180 <https://github.com/dajiaji/python-cwt/pull/180>`__
- Use datetime.now(tz=timezone.utc) instead of datetime.utcnow. `#179 <https://github.com/dajiaji/python-cwt/pull/179>`__
- Add py.typed for PEP561. `#176 <https://github.com/dajiaji/python-cwt/pull/176>`__

Version 1.4.0
-------------

Released 2021-10-04

- Add support for x5c. `#174 <https://github.com/dajiaji/python-cwt/pull/174>`__

Version 1.3.2
--------------

Released 2021-08-09

- Add support for byte-formatted kid on from_jwk(). `#165 <https://github.com/dajiaji/python-cwt/pull/165>`__
- Add sample of EUDCC verifier. `#160 <https://github.com/dajiaji/python-cwt/pull/160>`__

Version 1.3.1
--------------

Released 2021-07-07

- Fix docstring for CWT, COSE, etc. `#158 <https://github.com/dajiaji/python-cwt/pull/158>`__
- Add PS256 support for hcert. `#156 <https://github.com/dajiaji/python-cwt/pull/156>`__

Version 1.3.0
--------------

Released 2021-07-03

- Add helper for hcert. `#154 <https://github.com/dajiaji/python-cwt/pull/154>`__

Version 1.2.0
--------------

Released 2021-07-01

- Disable access to CWT property for global CWT instance (cwt). `#153 <https://github.com/dajiaji/python-cwt/pull/153>`__
- Fix kid verification for recipient. `#152 <https://github.com/dajiaji/python-cwt/pull/152>`__
- Change default setting of verify_kid to True for CWT. `#150 <https://github.com/dajiaji/python-cwt/pull/150>`__
- Add setter/getter for each setting to COSE/CWT. `#150 <https://github.com/dajiaji/python-cwt/pull/150>`__
- Fix type of parameter for COSE constructor. `#149 <https://github.com/dajiaji/python-cwt/pull/149>`__
- Add verify_kid option to COSE. `#148 <https://github.com/dajiaji/python-cwt/pull/148>`__
- Fix kid verification. `#148 <https://github.com/dajiaji/python-cwt/pull/148>`__
- Add support for hcert. `#147 <https://github.com/dajiaji/python-cwt/pull/147>`__

Version 1.1.0
--------------

Released 2021-06-27

- Add context support to Recipient.from_jwk(). `#144 <https://github.com/dajiaji/python-cwt/pull/144>`__
- Disable auto salt generation in the case of ECDH-ES. `#143 <https://github.com/dajiaji/python-cwt/pull/143>`__
- Add support for auto salt generation. `#142 <https://github.com/dajiaji/python-cwt/pull/142>`__
- Add salt parameter to RecipientInterface.apply(). `#142 <https://github.com/dajiaji/python-cwt/pull/142>`__
- Remove alg parameter from RecipientInterface.apply(). `#141 <https://github.com/dajiaji/python-cwt/pull/141>`__

Version 1.0.0
--------------

Released 2021-06-24

- Make MAC key can be derived with ECDH. `#139 <https://github.com/dajiaji/python-cwt/pull/139>`__
- Add RawKey for key material. `#138 <https://github.com/dajiaji/python-cwt/pull/138>`__
- Make MAC key can be derived with HKDF. `#137 <https://github.com/dajiaji/python-cwt/pull/137>`__
- Remove COSEKeyInterface from RecipientInterface. `#137 <https://github.com/dajiaji/python-cwt/pull/137>`__
- Implement AESKeyWrap which has COSEKeyInterface. `#137 <https://github.com/dajiaji/python-cwt/pull/137>`__
- Add encode_key() to RecipientInterface. `#134 <https://github.com/dajiaji/python-cwt/pull/134>`__
- Rename key to keys on CWT/COSE decode(). `#133 <https://github.com/dajiaji/python-cwt/pull/133>`__
- Remove materials from COSE.decode(). `#131 <https://github.com/dajiaji/python-cwt/pull/131>`__
- Add decode_key() to RecipientInterface. `#131 <https://github.com/dajiaji/python-cwt/pull/131>`__
- Remove alg from keys in recipient header. `#131 <https://github.com/dajiaji/python-cwt/pull/131>`__
- Add support for ECDH with key wrap. `#130 <https://github.com/dajiaji/python-cwt/pull/130>`__
- Refine README. `#127 <https://github.com/dajiaji/python-cwt/pull/127>`__
- Add samples of using direct key agreement. `#126 <https://github.com/dajiaji/python-cwt/pull/126>`__

Version 0.10.0
--------------

Released 2021-06-13

- Rename from_json to from_jwk. `#124 <https://github.com/dajiaji/python-cwt/pull/124>`__
- Add support for X25519/X448. `#123 <https://github.com/dajiaji/python-cwt/pull/123>`__
- Add derive_key to EC2Key. `#122 <https://github.com/dajiaji/python-cwt/pull/122>`__
- Add key to OKPKey. `#122 <https://github.com/dajiaji/python-cwt/pull/122>`__
- Add support for key derivation without kid. `#120 <https://github.com/dajiaji/python-cwt/pull/120>`__
- Add support for ECDH-SS direct HKDF. `#119 <https://github.com/dajiaji/python-cwt/pull/119>`__
- Add support for ECDH-ES direct HKDF. `#118 <https://github.com/dajiaji/python-cwt/pull/118>`__

Version 0.9.0
-------------

Released 2021-06-04

- Introduce new() into CWT/COSE. `#115 <https://github.com/dajiaji/python-cwt/pull/115>`__
- Rename Claims.from_dict to Claims.new. `#115 <https://github.com/dajiaji/python-cwt/pull/115>`__
- Rename COSEKey.from_dict to COSEKey.new. `#115 <https://github.com/dajiaji/python-cwt/pull/115>`__
- Rename Recipient.from_dict to Recipient.new. `#115 <https://github.com/dajiaji/python-cwt/pull/115>`__
- Add Signer for encode_and_sign function. `#114 <https://github.com/dajiaji/python-cwt/pull/114>`__
- Divide CWT options into independent parameters. `#113 <https://github.com/dajiaji/python-cwt/pull/113>`__

Version 0.8.1
-------------

Released 2021-05-31

- Add JSON support for COSE. `#109 <https://github.com/dajiaji/python-cwt/pull/109>`__
- Devite a COSE options parameter into independent parameters. `#109 <https://github.com/dajiaji/python-cwt/pull/109>`__
- Refine COSE default mode. `#108 <https://github.com/dajiaji/python-cwt/pull/108>`__
- Refine the order of parameters for CWT functions. `#107 <https://github.com/dajiaji/python-cwt/pull/107>`__
- Fix example in docstring. `#107 <https://github.com/dajiaji/python-cwt/pull/107>`__
- Make interface docstring public. `#106 <https://github.com/dajiaji/python-cwt/pull/106>`__

Version 0.8.0
-------------

Released 2021-05-30

- Refine EncryptedCOSEKey interface. `#104 <https://github.com/dajiaji/python-cwt/pull/104>`__
- Merge RecipientsBuilder into Recipients. `#103 <https://github.com/dajiaji/python-cwt/pull/103>`__
- Rename Key to COSEKeyInterface. `#102 <https://github.com/dajiaji/python-cwt/pull/102>`__
- Rename RecipientBuilder to Recipient. `#101 <https://github.com/dajiaji/python-cwt/pull/101>`__
- Make Key private. `#100 <https://github.com/dajiaji/python-cwt/pull/100>`__
- Merge ClaimsBuilder into Claims. `#98 <https://github.com/dajiaji/python-cwt/pull/98>`__
- Rename KeyBuilder to COSEKey. `#97 <https://github.com/dajiaji/python-cwt/pull/97>`__
- Rename COSEKey to Key. `#97 <https://github.com/dajiaji/python-cwt/pull/97>`__
- Add support for external AAD. `#94 <https://github.com/dajiaji/python-cwt/pull/94>`__
- Make unwrap_key return COSEKey. `#93 <https://github.com/dajiaji/python-cwt/pull/93>`__
- Fix default HMAC key size. `#91 <https://github.com/dajiaji/python-cwt/pull/91>`__
- Add support for AES key wrap. `#89 <https://github.com/dajiaji/python-cwt/pull/89>`__
- Add support for direct+HKDF-SHA256 and SHA512. `#87 <https://github.com/dajiaji/python-cwt/pull/87>`__

Version 0.7.1
-------------

Released 2021-05-11

- Add alg validation and fix related bug. `#77 <https://github.com/dajiaji/python-cwt/pull/77>`__
- Update protected/unprotected default value from {} to None. `#76 <https://github.com/dajiaji/python-cwt/pull/76>`__

Version 0.7.0
-------------

Released 2021-05-09

- Add support for bytes-formatted protected header. `#73 <https://github.com/dajiaji/python-cwt/pull/73>`__
- Derive alg from kty and crv on from_jwk. `#73 <https://github.com/dajiaji/python-cwt/pull/73>`__
- Add alg_auto_inclusion. `#73 <https://github.com/dajiaji/python-cwt/pull/73>`__
- Move nonce generation from CWT to COSE. `#73 <https://github.com/dajiaji/python-cwt/pull/73>`__
- Re-order arguments of COSE API. `#73 <https://github.com/dajiaji/python-cwt/pull/73>`__
- Add support for COSE algorithm names for KeyBuilder.from_jwk. `#72 <https://github.com/dajiaji/python-cwt/pull/72>`__
- Add tests based on COSE WG examples. `#72 <https://github.com/dajiaji/python-cwt/pull/72>`__
- Move parameter auto-gen function from CWT to COSE. `#72 <https://github.com/dajiaji/python-cwt/pull/72>`__
- Refine COSE API to make the type of payload parameter be bytes only. `#71 <https://github.com/dajiaji/python-cwt/pull/71>`__
- Simplify samples on docs. `#69 <https://github.com/dajiaji/python-cwt/pull/69>`__

Version 0.6.1
-------------

Released 2021-05-08

- Add test for error handling of encoding/decoding. `#67 <https://github.com/dajiaji/python-cwt/pull/67>`__
- Fix low level error message. `#67 <https://github.com/dajiaji/python-cwt/pull/67>`__
- Add support for multiple aud. `#65 <https://github.com/dajiaji/python-cwt/pull/65>`__
- Relax the condition of the acceptable private claim value. `#64 <https://github.com/dajiaji/python-cwt/pull/64>`__
- Fix doc version. `#63 <https://github.com/dajiaji/python-cwt/pull/63>`__

Version 0.6.0
-------------

Released 2021-05-04

- Make decode accept multiple keys. `#61 <https://github.com/dajiaji/python-cwt/pull/61>`__
- Add set_private_claim_names to ClaimsBuilder and CWT. `#60 <https://github.com/dajiaji/python-cwt/pull/60>`__
- Add sample of CWT with user-defined claims to docs. `#60 <https://github.com/dajiaji/python-cwt/pull/60>`__

Version 0.5.0
-------------

Released 2021-05-04

- Make ClaimsBuilder return Claims. `#56 <https://github.com/dajiaji/python-cwt/pull/56>`__
- Add support for JWK keyword of alg and key_ops. `#55 <https://github.com/dajiaji/python-cwt/pull/55>`__
- Add from_jwk. `#53 <https://github.com/dajiaji/python-cwt/pull/53>`__
- Add support for PoP key (cnf claim). `#50 <https://github.com/dajiaji/python-cwt/pull/50>`__
- Add to_dict to COSEKey. `#50 <https://github.com/dajiaji/python-cwt/pull/50>`__
- Add crv property to COSEKey. `#50 <https://github.com/dajiaji/python-cwt/pull/50>`__
- Add key property to COSEKey. `#50 <https://github.com/dajiaji/python-cwt/pull/50>`__
- Add support for RSASSA-PSS. `#49 <https://github.com/dajiaji/python-cwt/pull/49>`__
- Add support for RSASSA-PKCS1-v1_5. `#48 <https://github.com/dajiaji/python-cwt/pull/48>`__

Version 0.4.0
-------------

Released 2021-04-30

- Add CWT.encode. `#46 <https://github.com/dajiaji/python-cwt/pull/46>`__
- Fix bug on KeyBuilder.from_dict. `#45 <https://github.com/dajiaji/python-cwt/pull/45>`__
- Add support for key_ops. `#44 <https://github.com/dajiaji/python-cwt/pull/44>`__
- Add support for ChaCha20/Poly1305. `#43 <https://github.com/dajiaji/python-cwt/pull/43>`__
- Make nonce optional for CWT.encode_and_encrypt. `#42 <https://github.com/dajiaji/python-cwt/pull/42>`__
- Add support for AES-GCM (A128GCM, A192GCM and A256GCM). `#41 <https://github.com/dajiaji/python-cwt/pull/41>`__
- Make key optional for KeyBuilder.from_symmetric_key. `#41 <https://github.com/dajiaji/python-cwt/pull/41>`__

Version 0.3.0
-------------

Released 2021-04-29

- Add docstring to COSE, KeyBuilder and more. `#39 <https://github.com/dajiaji/python-cwt/pull/39>`__
- Add support for COSE_Encrypt structure. `#36 <https://github.com/dajiaji/python-cwt/pull/36>`__
- Add support for COSE_Signature structure. `#35 <https://github.com/dajiaji/python-cwt/pull/35>`__
- Change protected_header type from bytes to dict. `#34 <https://github.com/dajiaji/python-cwt/pull/34>`__
- Add support for COSE_Mac structure. `#32 <https://github.com/dajiaji/python-cwt/pull/32>`__
- Add test for CWT. `#29 <https://github.com/dajiaji/python-cwt/pull/29>`__

Version 0.2.3
-------------

Released 2021-04-23

- Add test for cose_key and fix bugs. `#21 <https://github.com/dajiaji/python-cwt/pull/21>`__
- Add support for exp, nbf and iat. `#18 <https://github.com/dajiaji/python-cwt/pull/18>`__

Version 0.2.2
-------------

Released 2021-04-19

- Add support for Ed448, ES384 and ES512. `#13 <https://github.com/dajiaji/python-cwt/pull/13>`__
- Add support for EncodeError and DecodeError. `#13 <https://github.com/dajiaji/python-cwt/pull/11>`__
- Add test for supported algorithms. `#13 <https://github.com/dajiaji/python-cwt/pull/13>`__
- Update supported algorithms and claims on docs. `#13 <https://github.com/dajiaji/python-cwt/pull/13>`__

Version 0.2.1
-------------

Released 2021-04-18

- Add VerifyError. `#11 <https://github.com/dajiaji/python-cwt/pull/11>`__
- Fix HMAC alg names. `#11 <https://github.com/dajiaji/python-cwt/pull/11>`__
- Make COSEKey public. `#11 <https://github.com/dajiaji/python-cwt/pull/11>`__
- Add tests for HMAC. `#11 <https://github.com/dajiaji/python-cwt/pull/11>`__

Version 0.2.0
-------------

Released 2021-04-18

- Add docs for CWT. `#9 <https://github.com/dajiaji/python-cwt/pull/9>`__
- Raname exceptions. `#9 <https://github.com/dajiaji/python-cwt/pull/9>`__

Version 0.1.1
-------------

Released 2021-04-18

- Fix description of installation.

Version 0.1.0
-------------

Released 2021-04-18

- First public preview release.
