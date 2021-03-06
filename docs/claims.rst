Supported CWT Claims
====================

`IANA Registry for CWT Claims`_ lists all of registered CWT claims.
This section shows the claims which this library currently supports.
In particular, class ``CWT`` can validate the type of the claims
and ``Claims.from_json`` can convert the following Names(str) into Values(int).

CBOR Web Token (CWT) Claims
---------------------------

+-----------------+--------+-------+-------------------------------------------------------+
| Name            | Status | Value | Description                                           |
+=================+========+=======+=======================================================+
| hcert           | ✅     | -260  | Health Certificate                                    |
+-----------------+--------+-------+-------------------------------------------------------+
| EUPHNonce       |        | -259  | Challenge Nonce defined in FIDO Device Onboarding     |
+-----------------+--------+-------+-------------------------------------------------------+
| EATMAROEPrefix  |        | -258  | | Signing prefix for multi-app restricted operating   |
|                 |        |       | | environments                                        |
+-----------------+--------+-------+-------------------------------------------------------+
| EAT-FDO         |        | -257  | EAT-FDO may contain related to FIDO Device Onboarding |
+-----------------+--------+-------+-------------------------------------------------------+
| iss             | ✅     | 1     | Issuer                                                |
+-----------------+--------+-------+-------------------------------------------------------+
| sub             | ✅     | 2     | Subject                                               |
+-----------------+--------+-------+-------------------------------------------------------+
| aud             | ✅     | 3     | Audience                                              |
+-----------------+--------+-------+-------------------------------------------------------+
| exp             | ✅     | 4     | Expiration Time                                       |
+-----------------+--------+-------+-------------------------------------------------------+
| nbf             | ✅     | 5     | Not Before                                            |
+-----------------+--------+-------+-------------------------------------------------------+
| iat             | ✅     | 6     | Issued At                                             |
+-----------------+--------+-------+-------------------------------------------------------+
| cti             | ✅     | 7     | CWT ID                                                |
+-----------------+--------+-------+-------------------------------------------------------+
| cnf             | ✅     | 8     | Confirmation                                          |
+-----------------+--------+-------+-------------------------------------------------------+
| nonce           |        | 10    | Nonce                                                 |
+-----------------+--------+-------+-------------------------------------------------------+
| ueid            |        | 11    | Universal Entity ID Claim                             |
+-----------------+--------+-------+-------------------------------------------------------+
| oemid           |        | 13    | OEM Identification by IEEE                            |
+-----------------+--------+-------+-------------------------------------------------------+
| seclevel        |        | 14    | Security Level                                        |
+-----------------+--------+-------+-------------------------------------------------------+
| secboot         |        | 15    | Secure Boot                                           |
+-----------------+--------+-------+-------------------------------------------------------+
| dbgstat         |        | 16    | Debug Status                                          |
+-----------------+--------+-------+-------------------------------------------------------+
| location        |        | 17    | Location                                              |
+-----------------+--------+-------+-------------------------------------------------------+
| eat_profile     |        | 18    | EAT Profile                                           |
+-----------------+--------+-------+-------------------------------------------------------+
| submods         |        | 20    | The Submodules Part of a Token                        |
+-----------------+--------+-------+-------------------------------------------------------+

CWT Confirmation Methods
------------------------

+--------------------+--------+-------+----------------------------------------------------+
| Name               | Status | Value | Description                                        |
+====================+========+=======+====================================================+
| COSE_Key           | ✅     | 1     | COSE_Key Representing Public Key                   |
+--------------------+--------+-------+----------------------------------------------------+
| Encrypted_COSE_Key | ✅     | 2     | Encrypted COSE_Key                                 |
+--------------------+--------+-------+----------------------------------------------------+
| kid                | ✅     | 3     | Key Identifier                                     |
+--------------------+--------+-------+----------------------------------------------------+

.. _`IANA Registry for CWT Claims`: https://www.iana.org/assignments/cwt/cwt.xhtml
