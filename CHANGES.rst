Changes
=======

Unreleased
----------

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
