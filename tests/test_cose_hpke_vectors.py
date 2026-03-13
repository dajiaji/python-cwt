"""Tests for COSE-HPKE test vectors from draft-ietf-cose-hpke-23 Appendix C."""

import cbor2
import pytest

from cwt import COSE, COSEKey

# --- KE vectors (COSE_Encrypt, tag 96) ---

# HPKE-0-KE private key
HPKE_0_KE_KEY = (
    "a70102024d626f622d68706b655f305f6b6503182e200121582064ea61f745f7deed186d697a"
    "4c89715932755017766348b0443a60aac450b5a622582088f53a4cbbcfcc1bf0b33d5dc60f78"
    "9a7f495244f57c158a8ceed5179639152b235820e8de39325f3c0be02442076c470a46bca742"
    "de9bc2be453ec1dc049dda1f6ca3"
)

# HPKE-1-KE private key
HPKE_1_KE_KEY = (
    "a70102024d626f622d68706b655f315f6b6503182f200221583003fcd256d1fd79ce8d6d29e3"
    "cb72a823380e1c655aa2ce211721245873bacb76eacd6e28f4557fed255246a76fdd61b82258"
    "304dd4aa71088792b44e00970c2f269c1eb546e848a6df2946e4409777deb6d7b77803a383c9"
    "e87757cef9f18910a1f76423583035172a2ccec0f1d1af547b811754e01de5406257ca808f2f"
    "abcbca5cbf7a4d22b951fc1d4da0e89e8608fde30d2f6706"
)

# HPKE-2-KE private key
HPKE_2_KE_KEY = (
    "a70102024d626f622d68706b655f325f6b6503183020032158420033db899e500ac6f1fb7a9e"
    "23f16a363e41b6d1f6dd5562c4faaa0491f1a74cbdbd039ff2b5824842d4da26c36173bc31ba"
    "2d1672699d871fdca27b9af0020bb580225842012ecb4d569869085618ce0a4e0f82fe9b618d"
    "ae8b678e26e7a1ed8d8b9bdf7ffcd32dfdee1bd85ee52097866c4f493a3174e6abb6b365057d"
    "212ce3d84a5010a6df235842019f28872f689d9c3a8018712e453a23beac37cb86c87e2c5a99"
    "d7e3901f2e4f4995fae274ca07748a7076d0ecae6466a7c3cdbc55d233544a59d22d3e4dde1d"
    "4b5f"
)

# HPKE-3-KE private key
HPKE_3_KE_KEY = (
    "a60101024d626f622d68706b655f335f6b6503183120042158202d925acfd0ee359a68565b61"
    "9165985a7108f7b1771131e26f11d24177dc9a3c23582060cb9ff63744acdac02a48527dfc28"
    "10fc49bc1223a240d870fa2d668c891155"
)

# HPKE-4-KE private key
HPKE_4_KE_KEY = (
    "a60101024d626f622d68706b655f345f6b650318322004215820a5922a701eebdf665a7877e3"
    "2b0651db5d3ad8eb4be792f2dfd9d9ac5d04956123582000f28ee18a4ddcdd4f318dd88ba71e"
    "fe0bb68002015e9c4879e99edf4e9c4b60"
)

# HPKE-5-KE private key
HPKE_5_KE_KEY = (
    "a60101024d626f622d68706b655f355f6b6503183320052158384489c1479ccd35343a90b3e1"
    "cb4922f73d9d611f12bf4abe9f76fcac6a6a974c0941fa602dfc29fb5c52b3191ea896162718"
    "d2ddbc97097e235838785cb877d73f034edaaa14d66dc3e10bc28d3ee5a290310c89eab7e347"
    "a82218874963600cf36850a389325fcbb6e4477dcc0f1b65e860d9"
)

# HPKE-6-KE private key
HPKE_6_KE_KEY = (
    "a60101024d626f622d68706b655f365f6b650318342005215838253b435291775cff909b2227"
    "b8bd6f539f521368b33871022f95713b4433df21becfffeaba9d63e839e43413e92689ead254"
    "feae3d7aa8e72358382c6894f63ec5d05047370d9415d4c0cd53ee2633926596788a41b5ff53"
    "68733b7d9499c391b08ed7c1c3d750c4c5af2ff03a44278c7c40b6"
)

# HPKE-7-KE private key
HPKE_7_KE_KEY = (
    "a70102024d626f622d68706b655f375f6b65031835200121582055137ef3179b4bba4326a5e7"
    "3ae0966d92d2ccc7e1714a66fba562a1c597a08d2258201daa17ff95d717128dc944069f4060"
    "af5981575734f1f847e6bd6bc30603cd6123582073294f0f394f08becf7358ea89c0cda596cb"
    "d9705a6b7c6f0ae8d70a9a85a913"
)


# --- Encrypt0 vectors (COSE_Encrypt0, tag 16) ---

# HPKE-0 private key
HPKE_0_KEY = (
    "a70102024e626f622d68706b655f302d696e7403182320012158206699b067898b7d2d37db0d"
    "a3aecad4bdac1558870b47d67d080d6049fb81752f225820b01b6da1f210f46e20e2b552a80f"
    "4f6b9a3adad34a6701f73fbbeffb174cf7412358206716e93d6594fbfd27016daada9ccc8e6b"
    "a2eea0e103e3d7ae22278f6dfe124a"
)

# HPKE-1 private key
HPKE_1_KEY = (
    "a70102024e626f622d68706b655f312d696e7403182520022158308309a370b333f956c1cff9"
    "d94e1ef8aacc2808ca898fec0476d9c132893704a2a4ecc88bd002e2c71383b97bb3ab658222"
    "58304b2a3e1b2fc832c136aee1632f967b31f5afd0a32c8c9766d0e9d0e4e2560a905278b0d9"
    "965898b3fe4d2165cfa1b1c0235830bde0361bbbf278ff3286a36897b2e674286870981ef471"
    "c2c81b55a3b82827800d32b34da68993cd590ff06e0788aeaf"
)

# HPKE-2 private key
HPKE_2_KEY = (
    "a70102024e626f622d68706b655f322d696e740318272003215842003c20a6d2990dac871dec"
    "57d8f31283ca99b9958a00e92ba43b1ff9186813f750b01333ef1f3119601875065599aa4888"
    "4425480a4d20e8e39bc84e98f745d91ed72258420058edb9dbccddc1594dc9003ab39886babd"
    "7ef7d0046aa72eae0f9c67b794c251c8a2309ae05f6f1cf4ac06045ecd45bc335d5c316936e3"
    "968e6ed42211bfdaa859235842010c50be4e0322d8bcb1424750f6ed3b22bcbe25ae9745a868"
    "688dcbbab97f522f5a95d0712b8d9ff48a5be6650179fd4e59913c76b1b28af9605ddb294756"
    "c2effd"
)

# HPKE-3 private key
HPKE_3_KEY = (
    "a60101024e626f622d68706b655f332d696e74031829200421582085eb6351a4e93a49953e1e"
    "23ade9504af68a73196a823c9a0654bf98c7536a7f235820f0b8ece6e3938430f36798eeea82"
    "06d0ac5e0577349ad63843cbbb63bc90b849"
)

# HPKE-4 private key
HPKE_4_KEY = (
    "a60101024e626f622d68706b655f342d696e7403182a20042158200191a45e7240233a4bda72"
    "ac8b38283aea336c863c7d5856b7df263038bc69072358200838e90c3407649faf0bd7eeb3e5"
    "a9fd7c643e4cb72b91997fc81d26d2f1de49"
)

# HPKE-5 private key
HPKE_5_KEY = (
    "a60101024e626f622d68706b655f352d696e7403182b2005215838fa09d4a5d1fa3a7b2b6de4"
    "3b08c715283d7425b80bf8b628b07d0d077283aa9c1507354e98c087688e8cfe7220be5e2d44"
    "509b2fd53b24e9235838b07f1d8cb1d2f3d5ba62c0ad5a1791e0fe79f6fdb9f49910274aa184"
    "855b67850ab2a53b39b131d07bc3d4e80a4f83b1c9f8f5f97f1fa598"
)

# HPKE-6 private key
HPKE_6_KEY = (
    "a60101024e626f622d68706b655f362d696e7403182c20052158380aff5f4a86fc468a25b771"
    "5d066628125dad13e4243f242cd6585f89f7371a55cfc3cf42cd3405a78dd380b4e9f4d47880"
    "c684deaa3f8aa923583898b6c98f0d48162ecc4c0f5e09c97246b03564a2672e12496f0f7a0d"
    "0576fbbdfb287b5a868e5b569a55b7d3765e5685feb7270471b13392"
)

# HPKE-7 private key
HPKE_7_KEY = (
    "a70102024e626f622d68706b655f372d696e7403182d2001215820df717fb8deae1b58b75448"
    "7c5432c8ec9a140dd11bcc7cd65cbe4b728e9263d6225820a8528d6143673203144a9636ea06"
    "5c60761390916f2218c8db958a64e263d3e02358202343a73ed3dc2b5e110d734c8d5e7a8b7f"
    "ea63849e78a8db3da48a65ecdb720e"
)


class TestCOSEHPKEKEVectors:
    """Test vectors for COSE-HPKE Key Encryption (COSE_Encrypt)."""

    @pytest.mark.parametrize(
        "key_hex, ct_hex, external_aad, extra_info, hpke_aad",
        [
            # HPKE-0-KE with default aad, default info, default hpke aad
            (
                HPKE_0_KE_KEY,
                (
                    "d8608443a10101a105507af5398f1827c014f68bdb9fe84152eb5821d25b7b5eb83dc30f3a4d"
                    "9ddadd9bd2726e88c621182d88ff53b39c5688c558f732818353a201182e044d626f622d6870"
                    "6b655f305f6b65a1235841040189cdaf807a039007db9e2984717cff68554f1bbe372d73a7af"
                    "89cad1b3b1ecdcfca75e2c3786ac3a7f61bf303395e2768b114ded2f4be39d40fff7917bb987"
                    "582011a6de6b6c1e5240a1035c1239c7a8b3000e7dc383818a97099f19b6c2b73b1b"
                ),
                b"",
                b"",
                b"",
            ),
            # HPKE-0-KE with default aad, default info, external hpke aad
            (
                HPKE_0_KE_KEY,
                (
                    "d8608443a10101a10550d68d7921fc2bf04d033edc091c7045f2582167788960ecb86bc44a71"
                    "b67d4fffabaa94c032e7b7f639cd28574b9080b817e324818353a201182e044d626f622d6870"
                    "6b655f305f6b65a123584104c73249f22b8c4171fecb3bd1093d3c6a1288aab904db50cb7c68"
                    "8a5dcb02ef22fc734d6091472016fe087bd0eaa71694821314321c6d193d842c220c7f58d819"
                    "582075ea467d773d97db62deb5fd1507607ee7ca47e467cedcd79f16a4072678713a"
                ),
                b"",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-0-KE with external aad, default info, default hpke aad
            (
                HPKE_0_KE_KEY,
                (
                    "d8608443a10101a105506a6c63e17b739c728d65b66d39e85174582118b37ca471a5306ba474"
                    "5b9578e6a8cf618bc01d7f4f9f16c28049dcb12027677d818353a201182e044d626f622d6870"
                    "6b655f305f6b65a1235841048115885e297b224f955c5ee9344c944801e8633e9305763125bd"
                    "0739656f6f0495af6bccb2c1e34d06ae586b186bdb618913e718456be702c2c84196ffee0624"
                    "5820e62641de898fa0534bfbaa671949554f6d9db266270b0cdd8b53ff4255353a1b"
                ),
                b"external-aad",
                b"",
                b"",
            ),
            # HPKE-0-KE with external aad, default info, external hpke aad
            (
                HPKE_0_KE_KEY,
                (
                    "d8608443a10101a10550f07d00afe300fe71beb752cadca5bb245821beed09dcab8c16c6ac26"
                    "ddf5df3d47c6638467cb231ba934882499db30a5073d7b818353a201182e044d626f622d6870"
                    "6b655f305f6b65a123584104b1d54393905a8551df3a675032b597ce40fa18dee7a4b11fe0ca"
                    "93524e4f20cd6de652360acc99e72f8b620039d33a9a1bdd542158a1a16b6d152264ddb701f9"
                    "5820602d1e4fac1cd619fd5f54bd625dd1861d80ddf6f4e220922616a05cc86018cc"
                ),
                b"external-aad",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-0-KE with default aad, external info, default hpke aad
            (
                HPKE_0_KE_KEY,
                (
                    "d8608443a10101a1055089035dbd98078aac856737fc9ce06eba58210c356b57b0170d371bf2"
                    "cfc4c5d648164036726f33498ff2c99b1cee42257a197a818353a201182e044d626f622d6870"
                    "6b655f305f6b65a1235841047ef0f70acf119a83c24b967af181514fae47996bd0eafb4d8641"
                    "e967802f28d58940fcfb4d28b4df4745a30700036b3bccc2ced18c1375865f421e583fb0a779"
                    "58202f93933dd09fb3db2cd287b738664d34bc263c89fab8aa6d46fa1d431814cd5f"
                ),
                b"",
                b"external-info",
                b"",
            ),
            # HPKE-0-KE with default aad, external info, external hpke aad
            (
                HPKE_0_KE_KEY,
                (
                    "d8608443a10101a10550edb91df2666a50b438779cbcd25ab4b158212b48ca390e8e5903e467"
                    "390347a8f4da0710ae6c66d90693083d8d62265b72fd5a818353a201182e044d626f622d6870"
                    "6b655f305f6b65a1235841041fb11d2984ca125db16fd99fd8c3f64862daee939a212fc68ddd"
                    "275ee75b5c25a4b71c73d9620951d9897410c2a9f2f19aa5932446ac9b36b0ae1e913fe7bcc4"
                    "58200eec5d2195d413e32a60b593008a85a0cc1ae74c63823feadd35eca3aba3786b"
                ),
                b"",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-0-KE with external aad, external info, default hpke aad
            (
                HPKE_0_KE_KEY,
                (
                    "d8608443a10101a105509ab67637694ffe1f4420ededf9a3e4ed582110b9cfa11046c7552443"
                    "3a693b8bcafea8522939afa042519495e46e1c40996869818353a201182e044d626f622d6870"
                    "6b655f305f6b65a123584104ae1c16e230410ce4f385288a7d83ebd0d12fa6760362e98c2c42"
                    "dde16f8caaea74971025d8b39bae72a127fd795068d7f3447a282d37295609e9b60dfa1a6729"
                    "58207ddfc787b9372d6ec0215a8504765947271074e6e81c48e2c6d5de95ac306526"
                ),
                b"external-aad",
                b"external-info",
                b"",
            ),
            # HPKE-0-KE with external aad, external info, external hpke aad
            (
                HPKE_0_KE_KEY,
                (
                    "d8608443a10101a1055012c4d08a6cb6da8dff2c072a152858875821064264f2652b166a8837"
                    "3bd9cedd96d38cb65c650726578910ae6e6e6313258f94818353a201182e044d626f622d6870"
                    "6b655f305f6b65a1235841043bf1b7f2d106d364416c27f3d7ccd03c3d803b9bd473c521456c"
                    "51f8c1a37b917584b861c100c42eb0eb048519bc10d675ac8013174e669af6bed0f814cb614e"
                    "58205c9e7e8f86b7ef1ba9f94425c9b0d8a7f43fc56df49da6b414629c2b7c96f489"
                ),
                b"external-aad",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-1-KE with default aad, default info, default hpke aad
            (
                HPKE_1_KE_KEY,
                (
                    "d8608443a10103a1055820aac05a4dcbdd92e82befd10b4724ef077579404dd106c4bc33c69c"
                    "b549cac1ed58214597a425b09b4ab5f169143378a5ff92169be65260098c5ae834659444d753"
                    "f672818353a201182f044d626f622d68706b655f315f6b65a123586104bc7ed2fa3f73a546de"
                    "2bae35fee30c39cad00e7883f85f2670a9eceb547262dfb8f676f701b7143a6ff693380b397c"
                    "23572dd677fc7bd6a5de005662ef9f8a3c335c81b69b59fa585a70e449ae581421ead6f7a0a6"
                    "d9c05e9fdcac0db1f60605583008e7f0466569e452d0f3e45aa99aa9dddeb04de6398fd55100"
                    "578046c27e15ba13fd2cabc5a33202ecd547a4c7b0c99e"
                ),
                b"",
                b"",
                b"",
            ),
            # HPKE-1-KE with default aad, default info, external hpke aad
            (
                HPKE_1_KE_KEY,
                (
                    "d8608443a10103a1055820c8ee79fb915867c74d950d05f6ca9d43d47f714936684ca7f0254d"
                    "7df92ba68f5821e74e07295b12fc4a8e518c5cff4d05df0bcfe55d29804c6eaf2a176ddec722"
                    "49f4818353a201182f044d626f622d68706b655f315f6b65a12358610463a670ebf1628d5a62"
                    "38c131aa98bee619c1d007aa703e3312eff22c2145a91f0dcb1e4787082e81720649780786e4"
                    "09fb9be9b7589d9d78e1d735cf1c664d47214bc1d4dfd06216c07a8ada1b3fe0f41fb759965d"
                    "65755dd59e74247561b19a58302115a5dcd6d165a7b30736723a4da24df149a89c0decde47e5"
                    "54abfc995b55a3eb89dd52d5059b96449ccd243fd93665"
                ),
                b"",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-1-KE with external aad, default info, default hpke aad
            (
                HPKE_1_KE_KEY,
                (
                    "d8608443a10103a1055820ac71a5659fe597a604fcc77a3d5b2b52bcd0d7d00fc5e157caf21e"
                    "a9666a1f685821052f34eacd31e88626a199ac533fd0308b74268a3cd320df3e8697e5cc9ec6"
                    "d211818353a201182f044d626f622d68706b655f315f6b65a123586104639aaa2fe678c4186e"
                    "9578c16dc72d6006ca8f7df7946b67843d7c4248da84d6a8ebb0f58fb84689c54b1f23c8390b"
                    "41e77d4bc4c93159ebc3a7810316ce505544ac2d81309fb45eb64a3401558921e37cd861aeaf"
                    "895e9606b066be1a609bea5830bb266370fdb5c56669e4c88c86329ea9a84dde052c9482e4c6"
                    "b305945d7c27e081b1d7cd5cd39c65ad4a4bd4bbeee875"
                ),
                b"external-aad",
                b"",
                b"",
            ),
            # HPKE-1-KE with external aad, default info, external hpke aad
            (
                HPKE_1_KE_KEY,
                (
                    "d8608443a10103a1055820172e4e1b4df69bb472d261bfb43c78433c330625eae7f4a4e31cf1"
                    "0b2ceeb94d5821ebfa1a3352ed030fc5fef08ae1c1066bc7d9108fd45def05396a6b4cd3401a"
                    "f48d818353a201182f044d626f622d68706b655f315f6b65a123586104a355c7e5fa4a166ff6"
                    "8825bf094e81b9744aa2518ce381721c329952f26bbdde60f5fbde96fa47258684bd7277e545"
                    "d3320b367ca06f42a56f6cf0afaaf1cb8ea96e4fa46b9db1dca72fd19988d9af9234d2b02a25"
                    "1eee800fcc03c260fa23205830d5f92ee2d4eff9323732c0fa70a071fa068c1572188b67ce14"
                    "01657ff32c1cf4d3bcb70d2144ba4cfc323e4f93d8b8bf"
                ),
                b"external-aad",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-1-KE with default aad, external info, default hpke aad
            (
                HPKE_1_KE_KEY,
                (
                    "d8608443a10103a1055820393f4c0886145f63d4de2012757a496b46f80da705c4fc7f045618"
                    "b2b1bbe74d5821a580ae1f89bd1b84e546d94628c97c3548118e74c5026eec543442b0bdf92f"
                    "1d01818353a201182f044d626f622d68706b655f315f6b65a12358610483ad6cd4932f0fc73a"
                    "7e0640b5db583082b0d741b64a948404adc5624e67e9167e9d81fd8d98e47afc006c2a366ff8"
                    "f1c4062565c8b1e9a2cfe791120addfa86ef6b444e957982a3f194fa2e932f6987b8ebf674b8"
                    "a96d5ebdde8a4edcd1fefd583088f136f57fa98c10df0b8a09d1ed6833a25e197ee653652f10"
                    "4265e20acf723bb2ff7daefc9db56f2120186c1d991978"
                ),
                b"",
                b"external-info",
                b"",
            ),
            # HPKE-1-KE with default aad, external info, external hpke aad
            (
                HPKE_1_KE_KEY,
                (
                    "d8608443a10103a105582086dbfa77caffcdcbc96b45ba891dd2b61a88ad0940ce5fdadf4452"
                    "6eb3b043ac5821a558899a7bc196b4b252f5cbf13a6d1ab2b45a083719ae0bcd3ac3cf16a45f"
                    "911a818353a201182f044d626f622d68706b655f315f6b65a1235861045cd0a1afae98177f0f"
                    "2fc52d75eb0acc5b4b8464ef7f14e8b0d90410f884496f21747e0b589b1fba09b0da8312476c"
                    "fa7492e4dff1258128b9be4cf6d8e94e972575935075767d186029a34d19115d4fd908565389"
                    "ecfd21a4a528eeecb1a7045830958ff6ee18bd7aca20198ba18b220658c1db5c67a2251600c1"
                    "eb698fd85812c271a5ec61be430a8c985c9d0922815e3a"
                ),
                b"",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-1-KE with external aad, external info, default hpke aad
            (
                HPKE_1_KE_KEY,
                (
                    "d8608443a10103a1055820d19b7e6c324f92b83ee77477d5a646cd88b986b8c6f83cdec36c7d"
                    "4892f7ba7958212d06813db517713f343ff5125ef2ac14c41b574b931cce50bd48b4ed3e2c5d"
                    "c8e8818353a201182f044d626f622d68706b655f315f6b65a12358610499890247ae97c42ff0"
                    "0408e71396e17ff114ac35f35849da6452c1cab3cc78186a65bfbf7a7c79e12c78f7c562af7a"
                    "b5c06ac4066f175c49d5992efab2c521c5d290549caee7d175e32d3f9bf1212b438c61eb8a01"
                    "0ea5956ff51d207d197fbb583064b27d50df0f0305c139c7545bb339b4341c099d40294b55fe"
                    "31ffd10d53ea9c6a58ada98a89b5b7a2419434df7e6f16"
                ),
                b"external-aad",
                b"external-info",
                b"",
            ),
            # HPKE-1-KE with external aad, external info, external hpke aad
            (
                HPKE_1_KE_KEY,
                (
                    "d8608443a10103a10558209f03b841a61b17bf41e3afb0109933abc9750cf9a5f6d690a96283"
                    "c9a8b30cf05821613a6eda5df30ef01a9d5974dd0f28598f587803a0e644cf22f5b78e42f38a"
                    "9259818353a201182f044d626f622d68706b655f315f6b65a123586104f85e706f0b1469fcc2"
                    "bad6a25cb801418954d78344bf56e855e4d0241dc654d4050e224480e99644949875243cdb0c"
                    "ce4ab352e6e9ff3106fec195fa4bebe994da650208b34b55b2f6a433609d6343d43e5a8abe8d"
                    "b28dc06f665cdef59984a15830a817dd751be11ed8596225bed31887383299ee632cbe319443"
                    "a2b6f3bab515884c423e0af2a29e7db0ee13daad9d69f8"
                ),
                b"external-aad",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-2-KE with default aad, default info, default hpke aad
            (
                HPKE_2_KE_KEY,
                (
                    "d8608443a10103a105582036694bc81347438c501dc55add947708ba52ce8bb52aa7b2878d26"
                    "a0b9878d855821e6032422deb9c62db49d50c0011197c39b586660b7a018443f1ab285f70701"
                    "9f69818353a2011830044d626f622d68706b655f325f6b65a12358850400d55b883bb4f6f54c"
                    "b0f147826fb706f01ccb19d67a8df4ce4bdf451f39ae2c4e77370558c529c2022dd39e07f36e"
                    "315705cafe57249ac9abd1fe0fd821a366bce6013a2b390c1d3bf50f47cf19df06ee0564716d"
                    "bc589c325a46fb66526167710a82a4e40c55629fb48619dde005fa002b994b240ab481c37aa4"
                    "170f7d38c61674eee95830933543fd556de228367ef1d4b1b6407461bd4a7acede97d25ebf67"
                    "590078cc3fe49408300ed29d23be1c27b2902317a8"
                ),
                b"",
                b"",
                b"",
            ),
            # HPKE-2-KE with default aad, default info, external hpke aad
            (
                HPKE_2_KE_KEY,
                (
                    "d8608443a10103a10558201d84edbb7cdff030f465bfce04a1e69e888bb092d660fc78377545"
                    "91aef06e4158218fdcf224296ba502062f6029071f5f120ce2f8f3ba20e81052a9e34dbda210"
                    "26ec818353a2011830044d626f622d68706b655f325f6b65a12358850400c2d331ea52e37a71"
                    "ca3b32abf85f25ef92ac398c806de067fa344a97b111f00677a62ed2eac2d540e5685279ec03"
                    "ee69a6b23ed78baf8229b7aa83d76318d86b7a0142ad7baf09f065fafa8c887a5151272fd219"
                    "d9c0b7caebf4f4e1532e261b5df4e5ce1b6ccb5dbfd86f5a6d7f0c34eb7f2da17b89831ebbf5"
                    "6791d18fb305c0197f583076cf3e4a3ff03606752d6b7e09806c02aa35a4677452bfd0dbd1a8"
                    "abb9de682978a6d0ae2be5685d4ca48c85b5b2c0e4"
                ),
                b"",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-2-KE with external aad, default info, default hpke aad
            (
                HPKE_2_KE_KEY,
                (
                    "d8608443a10103a1055820ef1d313af4d977ec69da4dec5fb387920fb5f0e1843dab998a24ee"
                    "94aa47a119582186a225225aadeed9ed918e6d1f48c4697e10a07085aa6fcbc0fdff18189b85"
                    "f361818353a2011830044d626f622d68706b655f325f6b65a123588504004074fd0f72b72379"
                    "66abf252c0e41a21c5566e0f8c94c2a86c6d21e16035c57a887e5f69a3adf44a1580992bac71"
                    "6f2693a8fd3771043b022d016771b0498569390168f4cd133158b2da000169f8676e3499161f"
                    "35be790f7c26bd984b339b00ce505c18b3470f0e159741d63a1fe106eb1ecb6ca50c8130670f"
                    "28c97bfc625ff33eaf5830935ea79f6e36fd6785bcdbcdcfc737f01400d1262aadf8f2814a12"
                    "3cbd5a498550f3f30978aad8c71b5dec58238e9d61"
                ),
                b"external-aad",
                b"",
                b"",
            ),
            # HPKE-2-KE with external aad, default info, external hpke aad
            (
                HPKE_2_KE_KEY,
                (
                    "d8608443a10103a105582050ffa1a4eddc067fa06db21366dc53f4746d1d7b4f9fdb9e02532c"
                    "80591e621258217c27fb226998f944de516cd7a13509aed1070e72bd4639f955efe6626a202e"
                    "c97f818353a2011830044d626f622d68706b655f325f6b65a123588504004a73a294d7a1c966"
                    "85a9ca89dd657afddb2fd8263474d5d020d46a59ed66290770b6e7989c60f800eeef64de8f82"
                    "3c9e40c99b5deee652b5c5d450b9ea127dc006009e49e147db35cae26ab891572765c4fc5889"
                    "62d0f71c046c3f7f627f09a41e9e682d0d1740720ee8b73adb777c44fdcf4c343b08aaf01849"
                    "c32ae4cdaa56e04a895830609a822ab35ac0e183c1049d0e80556d443c8a6f80a27da55f8c34"
                    "605c240b720dbeafe4961fd95eac09dafa4c090de0"
                ),
                b"external-aad",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-2-KE with default aad, external info, default hpke aad
            (
                HPKE_2_KE_KEY,
                (
                    "d8608443a10103a10558208abd74a6f6494dca72c2dbdbd5f7771a508fb43adf777208e7dc82"
                    "8a9ccf024d582133db1cbe20bb05829a6f1a2d4bdad78d4b3c9e10dd9d3de106454fbd6b9673"
                    "61ee818353a2011830044d626f622d68706b655f325f6b65a123588504012af1fa72a02b73aa"
                    "86229266d417f82dc19c55ff550f122e354dc3c7866aef669f26cf2b57f9b9d3f373903dd1d0"
                    "ef0c5189d41aa7cbfd4bfc4c955e5727420b980076484702ecfbf448298ffa72d1d31f36d9df"
                    "d629104e5bd5f226c6fb992fa75451d0114144b1908e93a3d5c5db83064bf973c9ae2f7876b6"
                    "69a55e49a3dc9bab21583040424efb8c1c3827fe491bc7e426dff929402372dcb44e5b29103a"
                    "b7254204367d72f56df75003b07fe4294b93fdc2a6"
                ),
                b"",
                b"external-info",
                b"",
            ),
            # HPKE-2-KE with default aad, external info, external hpke aad
            (
                HPKE_2_KE_KEY,
                (
                    "d8608443a10103a10558203099a01f838a003fc9119ee15835749011e099d23026f134a96b0e"
                    "c2a99711005821aa17b650a15695339c627f95080f37b0e27bdd56d758636cedf5ffa1028490"
                    "f407818353a2011830044d626f622d68706b655f325f6b65a123588504015b3422b8aa732b57"
                    "dba50e817eacef848ac0f6f9d41fe2496512442044cf5cea24778deff337c76b26fe23f7f382"
                    "0d95e22766d72e2ddfc54750c6c1089b585e250043c612eeaf05c49b1df18066f8b4925d287c"
                    "3b36b6177206b8964bcb9d2aab62c77117444ccb4164c7e60e07df0a00ccd28f19747c3d1b49"
                    "99055a215e06dd0efc583046501065f28c600ff9872eadec2c958d4435edbf3c6aef7fe8b01b"
                    "6b7fe625e53e0186a9d52b26573031b49009ae1808"
                ),
                b"",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-2-KE with external aad, external info, default hpke aad
            (
                HPKE_2_KE_KEY,
                (
                    "d8608443a10103a1055820d6571aef69ca1d95c29f8e32138f3b4cf73d6de02bd42f21c5c245"
                    "dd1281e95d5821aaeb110acefa649d60730cdf59fdfbfe99d4cd468f0af79912a996d6fc6294"
                    "6107818353a2011830044d626f622d68706b655f325f6b65a12358850401a18bb1ccfe763604"
                    "47ac01c17cfef513f41ab8a9d621aac0c3f1cd523fc15748ba0aa4526745260f918826fac568"
                    "c9c1788db3ef20cabcb60d057ec4d01f7146cd005e52a1743fce60440f6a7e630165bee4bd70"
                    "59ea01781488bf397416920d33f55f1cf0d01c89a90611c5a5a07cf493d693b02266d743a972"
                    "652ca94e8652fa52ef583011f8320f59b91a8aee140d2edf61e0da9db310e42759577c3254f9"
                    "27b7d83d85d2632a955ab4e1bb2c5093b37a8ea138"
                ),
                b"external-aad",
                b"external-info",
                b"",
            ),
            # HPKE-2-KE with external aad, external info, external hpke aad
            (
                HPKE_2_KE_KEY,
                (
                    "d8608443a10103a1055820ebd94a697400c2eb88607a0bc538915e63f5fdbe4f528a11e55924"
                    "4b773da7115821af4eb2942d7596739651bb60b4de3c456cf74296af3cf0665de158cfaabba1"
                    "b188818353a2011830044d626f622d68706b655f325f6b65a12358850401db35d812f17987c1"
                    "1a82fcc40bb40c540a7ace9c35b4da9b65dc03ef67e2199b066a3ce082f9da9f596b73daf89b"
                    "643756f8e29df45d0b78b002ba1d96f2661b78005472f944fd1172c93c04df2e8a6452ddf5ba"
                    "4c932d17604b58591903de3f60c28557a781269ce31779c1f2d752ec1fe9fc6ffdcdb6f21a71"
                    "e6ae5969d07fffc0fe5830d96f3bf5629c8c9cf315cac23cdf75c72c013df31434f9999eb285"
                    "2111faa0d3c36c5e7f1b5ebd81b0644c38ee8e3bec"
                ),
                b"external-aad",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-3-KE with default aad, default info, default hpke aad
            (
                HPKE_3_KE_KEY,
                (
                    "d8608443a10101a1055057c9f2b6225deca6982d8f501953628a582168e4b863ae09e0179dfe"
                    "7368d92c0e998ba891791004ac55f05b81fca899dcb975818353a2011831044d626f622d6870"
                    "6b655f335f6b65a123582071075e8a1b304ef9edbc2936f6e5be4ac2e4e7ad59ad37d748fb58"
                    "0bb5fc5c5858205b3704e4c7fd8f05c51fde7f159e701aeba21c55b82dec0e42b9bf9a6a9634"
                    "c4"
                ),
                b"",
                b"",
                b"",
            ),
            # HPKE-3-KE with default aad, default info, external hpke aad
            (
                HPKE_3_KE_KEY,
                (
                    "d8608443a10101a10550320b164a39702b84ad08f8e9b741445658210a1cda2aa5fab6fde702"
                    "6ef7fbef3faab763d7e3ef2b06aa09ca08b4de09a15d84818353a2011831044d626f622d6870"
                    "6b655f335f6b65a12358209e0d94bb2d354bd6a83b9374d9984be125bde4ae96230eff1d10d0"
                    "254e96a97d5820b3aee0a1d634043403d61ba332ddf8fa899430e0221ba127eec76399a026a3"
                    "59"
                ),
                b"",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-3-KE with external aad, default info, default hpke aad
            (
                HPKE_3_KE_KEY,
                (
                    "d8608443a10101a105508c0eca59bd53bffe5ef3b539c4ea5d6b5821e60895c561cfc588bbd1"
                    "24dbdab7bd2a19590f93e712f6bb3f745c6c8912366ce2818353a2011831044d626f622d6870"
                    "6b655f335f6b65a1235820a141613c5ce54168fc1b9d76a4a28b6461c8b65a14220086c3da27"
                    "04ca0406695820bdd73f84ffb4d11d4d92391dbb34fa8db2ee4f81299203f529f98ce52e49de"
                    "86"
                ),
                b"external-aad",
                b"",
                b"",
            ),
            # HPKE-3-KE with external aad, default info, external hpke aad
            (
                HPKE_3_KE_KEY,
                (
                    "d8608443a10101a105502ff672957f5586fd4a08d0fb045c6639582122758f93e861925e3e40"
                    "dab68a550046043c0b6183690696116b93093888e52ed1818353a2011831044d626f622d6870"
                    "6b655f335f6b65a1235820a95c290e4366159abd5141943341775f58521efc1ab15015bd368f"
                    "10bbd5a53f5820c540b2af48b165f272a72d3a133846d6915627cbf3a37db34a312cd86cb5a9"
                    "f7"
                ),
                b"external-aad",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-3-KE with default aad, external info, default hpke aad
            (
                HPKE_3_KE_KEY,
                (
                    "d8608443a10101a105503a42e93d02472760b51fb62b464b4b9a5821ac8e71b022b24b228857"
                    "9ef0c1c854afd28b74e9e784fa5d2f1528c477a0c90740818353a2011831044d626f622d6870"
                    "6b655f335f6b65a12358203c9268ad53ea237b648a1806d667a45f74dcb725c7777fc558d456"
                    "6cdeaadf605820dd50847d57ba2906c45b3365153bf93cad6dc9dc049fca46d91ac07a5354c0"
                    "69"
                ),
                b"",
                b"external-info",
                b"",
            ),
            # HPKE-3-KE with default aad, external info, external hpke aad
            (
                HPKE_3_KE_KEY,
                (
                    "d8608443a10101a10550dc32f24a9fcb7dd8da12372b7ccdf3505821ad11bf317640a6c1051a"
                    "c0453ef9994a9a8a21dc34f2bb8ad17ac17bd902dc420c818353a2011831044d626f622d6870"
                    "6b655f335f6b65a1235820bbca5f776f840f0c4eb5f1994c99892fd595f9df6e45787550a162"
                    "4d3a3468255820140a9c10b359b476982d18f7f0fe3863845501a020fc311b8a8a513df115ac"
                    "d6"
                ),
                b"",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-3-KE with external aad, external info, default hpke aad
            (
                HPKE_3_KE_KEY,
                (
                    "d8608443a10101a10550b224ec850a723d60cd6fade231f03a7058210e151c37f85bff7b382f"
                    "d4158339d10bc1746a7d26dccf21d37e122f45456641a0818353a2011831044d626f622d6870"
                    "6b655f335f6b65a123582056e5dc366ead34698fc0b4071a7406c6910beb1e8292b3dd9436ae"
                    "34b653a0055820edd2498d3dae8e148360ea18f07d59e0adb4d283519d9d4b3820c9148f5bcd"
                    "5f"
                ),
                b"external-aad",
                b"external-info",
                b"",
            ),
            # HPKE-3-KE with external aad, external info, external hpke aad
            (
                HPKE_3_KE_KEY,
                (
                    "d8608443a10101a1055062670829c5fc6f5cdc48faab828dc09e58211ed421e07f98eca98f11"
                    "55790c790e6710a53484310a47f3b7afdbc77b5a7cb5a4818353a2011831044d626f622d6870"
                    "6b655f335f6b65a12358204370a8614e9d71a82998498493fedbd974def1ba2f3ff34feb5c8b"
                    "bb1898484c58201e284bb8a5f35206429c5326036316a4c4dcd5772b7ed9dffdd1e3cfe02ad9"
                    "fb"
                ),
                b"external-aad",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-4-KE with default aad, default info, default hpke aad
            (
                HPKE_4_KE_KEY,
                (
                    "d8608444a1011818a1054c06361aad32854c99401d9613582107f6ed7364a443fab2dc1710de"
                    "081e8e535d621ab98d45e92cd15ecfac213dff6d818353a2011832044d626f622d68706b655f"
                    "345f6b65a1235820ba1cbbf9ccacde066147b54ea4c28806c41add5495c37295d520d5332d24"
                    "7102583022d9d848d1e3603de56c4a3a0ece5ca75e6a51b929d28142a53067f6169001da5320"
                    "bbe23facb5c4f6f428f35c4af1cb"
                ),
                b"",
                b"",
                b"",
            ),
            # HPKE-4-KE with default aad, default info, external hpke aad
            (
                HPKE_4_KE_KEY,
                (
                    "d8608444a1011818a1054c9c4cbe7dc327ce468d50bd9e58216f145b2851c502d5b0c3ce4bcd"
                    "99e96299e2aba606e2af70338c91b31c68a7613b818353a2011832044d626f622d68706b655f"
                    "345f6b65a1235820e1e167e1917be9aa3090108e145a03d0fd204242800da4cab096573fb5f4"
                    "f164583071397ad12d2a974dd23eaa363f40d3c59c6e706b6b4c8d2a4ec4a6de92e860c30552"
                    "336591bec0a8e51fe293bca83740"
                ),
                b"",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-4-KE with external aad, default info, default hpke aad
            (
                HPKE_4_KE_KEY,
                (
                    "d8608444a1011818a1054c3d211831f229feb2b70db089582105a0acb03ea75dd18d53bf05e6"
                    "48260c91c890355985a11d527eb8c4189590b08d818353a2011832044d626f622d68706b655f"
                    "345f6b65a1235820c18fb4814d1f116b82836aeb213bd3528ae6a2417da08cc5abb6b1557521"
                    "7b345830ec408b0789d9097e9be5101e9e84a307608955570547964d2d840aecef4590936147"
                    "7ce85b012d4ad0d3bd9b2fad9101"
                ),
                b"external-aad",
                b"",
                b"",
            ),
            # HPKE-4-KE with external aad, default info, external hpke aad
            (
                HPKE_4_KE_KEY,
                (
                    "d8608444a1011818a1054ca3a0a911408279f90ca90b0858214cbe2773a824c0e526c75dfd20"
                    "285b2cef1d39605ff9b64e4f3e16ba943e237263818353a2011832044d626f622d68706b655f"
                    "345f6b65a1235820e2d8f154d1a40c518058770f0f345b9d448b418397ccc42d2af887ae9c13"
                    "7210583016932c4f4a574d2ab03dc02729dbaf404330a21df11e1ebc2e52c462e48fed0a0cd3"
                    "219bff3e9eef5fdc19d92aad161c"
                ),
                b"external-aad",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-4-KE with default aad, external info, default hpke aad
            (
                HPKE_4_KE_KEY,
                (
                    "d8608444a1011818a1054cd7ab613f6cc110a022aaba5958210a1b3f842a6c339bc939bea0ec"
                    "5a0f265777f67d8bb4b826252b6252ba4cdfc6db818353a2011832044d626f622d68706b655f"
                    "345f6b65a1235820f8fec4f5ada1c6f6a6b1ee9b89092200c8a481daccfb51fd47b4fa997094"
                    "27465830cd5b8342f3727d7afa5b981c7be6edeaada728833f801ec658cc77763d6de36af711"
                    "22a250c5edf7df853c54dc486fe9"
                ),
                b"",
                b"external-info",
                b"",
            ),
            # HPKE-4-KE with default aad, external info, external hpke aad
            (
                HPKE_4_KE_KEY,
                (
                    "d8608444a1011818a1054cff6ec38f45005c1d36229a2858212291e110fe7cca10f0258abfa3"
                    "1dbb9c8d019f88dc297f7a1641474650db40ec82818353a2011832044d626f622d68706b655f"
                    "345f6b65a1235820e6fec434687bc3b5cd0597c4a56d76c325fb8c21d4dfe8e7aaa47b4572c5"
                    "8f4a5830167720e484a884f32f961544bc2fa865cbbee622c73bc98424871e7dcc9e7dbeb8b5"
                    "0edc8f6bd499a0e08b9bdb916841"
                ),
                b"",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-4-KE with external aad, external info, default hpke aad
            (
                HPKE_4_KE_KEY,
                (
                    "d8608444a1011818a1054cbde082e4f5995e02d5ecfa6d582116efe45e6ac45104adf41a3d46"
                    "a627ad743f8178a0a326ddc1431d030172bcd35e818353a2011832044d626f622d68706b655f"
                    "345f6b65a1235820a7252d0db32722de877846fefc59ceadd29e698db423ebe3577cd6c0af19"
                    "5f675830520b088ea067725bfeb093abd31bb75164233a499171855f3d68cd93cad466d56fc2"
                    "9119c475b10e29a69951163383a1"
                ),
                b"external-aad",
                b"external-info",
                b"",
            ),
            # HPKE-4-KE with external aad, external info, external hpke aad
            (
                HPKE_4_KE_KEY,
                (
                    "d8608444a1011818a1054c2bf44cdd95f7de613426342c58210fee2d9d95bf69355ff8854518"
                    "49a0dad422dcb3cac652e11413bb87a16da8c333818353a2011832044d626f622d68706b655f"
                    "345f6b65a123582063915e953e2d4a681251ae4e19fb61d4d0591cb6cba32d989ec97d0d9c65"
                    "841a5830c8fc0abec5ee853241c63be826b682119856d9dcc511a0aa4ae5121555afe6198071"
                    "6cd793312fa52ca130649e8b69f9"
                ),
                b"external-aad",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-5-KE with default aad, default info, default hpke aad
            (
                HPKE_5_KE_KEY,
                (
                    "d8608443a10103a10558205972218d130ebd50902f975638867f4393a02ad5fec6acea3b5acc"
                    "14b99e7d6f5821e0d433a3f90df4a6bf252d8375c02ed940ae6321ac116865e8a698e3e9826ae"
                    "00e818353a2011833044d626f622d68706b655f355f6b65a1235838a5617b199ab5a27633ca06"
                    "3f171039bbbbe50e1563630270f5608b1c80b3add4658ee958f71bef28abe39e20231df1b2a5"
                    "fdc6e5c7cd4c4258302f8f8d8b1f3bc43d53dbb260c3930310300d4ed07d04702c4e2114e7fcb"
                    "c27cffe87c754455bb52c2e0d77ffc49f3424"
                ),
                b"",
                b"",
                b"",
            ),
            # HPKE-5-KE with default aad, default info, external hpke aad
            (
                HPKE_5_KE_KEY,
                (
                    "d8608443a10103a10558200ea58687a765e595948d0a4f863ffe895ed35afcc292f8e5f09a59"
                    "666c018f87582153e80b1f3f78c46d298c2d969bb438269f56fb0db3f8b0dfbc3ce64d9bdb91"
                    "0905818353a2011833044d626f622d68706b655f355f6b65a1235838d9d4ce1da2bb47ce71c0"
                    "92855f2982a108793dad43b58ad4f378c35e50ae960124ec906f02e959783559b189d73b4245"
                    "bf6d12a291a66f2b5830816961b03ac6df31f593d4e3b8cca193e330d5ad273cd8e4fe1355c6"
                    "85c0b2a804fd8b5871346c3a640df51e2885aafb"
                ),
                b"",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-5-KE with external aad, default info, default hpke aad
            (
                HPKE_5_KE_KEY,
                (
                    "d8608443a10103a1055820febe825f97612663cb5b37322f6d27a4a69cfb984b770391db1ddd"
                    "4351c565ea582163f837fa3fc30525c6dcd8fd38b0fdf4cb0732726d4e48479faf4cd19c106c"
                    "b61d818353a2011833044d626f622d68706b655f355f6b65a12358386d8ab86baef7eb8b1b4b"
                    "9812b8ee20de9bb7665db246a4058d557ef7b5a175378825d6c3878cfe4cded34a63cd3f23b0"
                    "c0a486fd742824af5830a5ff5e55b20975bfb4288eed91aae3181599c9444f56bd7d845e537f"
                    "75e0001b860939ff406e3de872af20939444fb97"
                ),
                b"external-aad",
                b"",
                b"",
            ),
            # HPKE-5-KE with external aad, default info, external hpke aad
            (
                HPKE_5_KE_KEY,
                (
                    "d8608443a10103a1055820e651daaf30ef27e8898bd2f0f71eb81105a65ca9d625deba0ff73e"
                    "fa5518a0fe58216f7ed02b0a8c3be5f2e2d15bd58c357c65b688cace33d2e50e7a5e48a20b16"
                    "12f2818353a2011833044d626f622d68706b655f355f6b65a12358380f782ab1db5dbdff4310"
                    "356362f1fd48c0cce05f4cf5f10ed17dd4ef5489513a63d3f357875f8d4f80c8c44afcb46897"
                    "b623ef3909a043e358304fdb1f7cc531e49ff9d6fb934a0a56b0c39fb161802304ee2d6aa2e0"
                    "38b7a1f604c643cfd3ba046f85579e06ad7e58db"
                ),
                b"external-aad",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-5-KE with default aad, external info, default hpke aad
            (
                HPKE_5_KE_KEY,
                (
                    "d8608443a10103a1055820bc667687a2c9ba3a67811138b684871cc443c3a656602b8c7fa229"
                    "e73fd873f358218bf0c9204e988d76554b1195baee96da10ac58867a1daa775eefe9710307bc"
                    "4cec818353a2011833044d626f622d68706b655f355f6b65a12358380e5096bad10fa4fcdd44"
                    "0552c14da49d819eb5fb2dd333ee59cfa845f51406d7cab97f61a5c852b3312fddbdf347cdd6"
                    "6d0ac3fd6aeba8825830a961291467b70f5ba8e1c02417d0048f3f2000ac4dc11722d8cd88b7"
                    "5e0dbf7c084740adacb62fb7b10b8b15649dba17"
                ),
                b"",
                b"external-info",
                b"",
            ),
            # HPKE-5-KE with default aad, external info, external hpke aad
            (
                HPKE_5_KE_KEY,
                (
                    "d8608443a10103a1055820330886cc981a8fc93e5f508127f1adfc8d4db541d3618c887ddc4f"
                    "8ac952b78c5821652e76d1029e9749fdc28bea647b1e3e3d62bd57676cfbe857b84703a1c5a0"
                    "7b15818353a2011833044d626f622d68706b655f355f6b65a123583846c302c3731504388199"
                    "bc3e885b9fac2171f59c1f9cafd8b909f6b5f7d3360f261101400b33c8c10b5be896d2b2bf2d"
                    "c324018be31a46175830b11375f3eac8a4f569ea3e6c31f8a27deeb029d54597496db6fbd2e8"
                    "53b59e1ef1fc30c312e7d0b6f482558d95f9bb5c"
                ),
                b"",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-5-KE with external aad, external info, default hpke aad
            (
                HPKE_5_KE_KEY,
                (
                    "d8608443a10103a1055820968e5870eb26e9e8777dafb83becedb4c9ee1ac75e57b9635739e7"
                    "ba96925d7c5821d65d8d5bb8922d7e16a6ec3a0a2c7b6432c569510a946953c891442704e3db"
                    "ba78818353a2011833044d626f622d68706b655f355f6b65a12358385545cbe1853c1c43e456"
                    "f5fefd73004bb1d21684970adf8f8fbaa9681b83576780d138948bb82b1094fdbac6c3388cd8"
                    "247acf1493e969f458306c2f2c32734dd4f6af964e9546d0a642107831b5c4bbf0b8edb87e38"
                    "e3755e2da85b1e8f14097d51159b7df7cafc34f8"
                ),
                b"external-aad",
                b"external-info",
                b"",
            ),
            # HPKE-5-KE with external aad, external info, external hpke aad
            (
                HPKE_5_KE_KEY,
                (
                    "d8608443a10103a105582012c4b7c5277a67a1f0cd348eaead14678fbb47428daebc43426b56"
                    "30bbc08bbc58217d6af626389f2eecf2cdcff8d3716033aab7a922a1b3e6ac66edead54f7c45"
                    "1284818353a2011833044d626f622d68706b655f355f6b65a123583840a712d7894f87c5c5dd"
                    "263a97bafb6fcf06e22e9ed801a1034aada201fe9c1a49e8e073746f6c713306f00c4335ebe8"
                    "c9159910c659610c58303b5eefa35efee50c73134120b7f24bfe68936b628c78291208608744"
                    "1754d408fa877cf15e4374a8c3af19a048df2896"
                ),
                b"external-aad",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-6-KE with default aad, default info, default hpke aad
            (
                HPKE_6_KE_KEY,
                (
                    "d8608443a10103a10558202b413539e41b5be049097d8c7336c564da6910493f34cac7be758d"
                    "9be0bbc2a45821895a2fe91419e7f4e56cdad089d97b4313fd4d64b50751aa35b8ae2a5a1f0f"
                    "49c0818353a2011834044d626f622d68706b655f365f6b65a12358389e4bc52535fd7d7de199"
                    "cd9d3bc1ead38132ce559491daa8291ae62e27a305cfa0e5301c44ada163e8c6d003cc201d84"
                    "d6e56a0fbbff09aa5830386b65b7d4658bb2cc1cb93e05d94685cceec0f155d39f46b74fd67d"
                    "b0ede3aaf653f5d44a79b2bc0b5c5c186f42a0e4"
                ),
                b"",
                b"",
                b"",
            ),
            # HPKE-6-KE with default aad, default info, external hpke aad
            (
                HPKE_6_KE_KEY,
                (
                    "d8608443a10103a1055820c38056dd0acc795392719d75883a9efa306688289e317fbcaa907a"
                    "593ef7fbd058211d3a68fca3448e77c0350164e7ccef263ddf6e52c00b5d7467137987d9322b"
                    "0edd818353a2011834044d626f622d68706b655f365f6b65a123583873272b13d50c86ade06a"
                    "d70f4067d8b9dd546dea6699cb8937b79106a2d178c6e3dab8b403b60a05efa417ddeb14e97d"
                    "cb8b46c866ec027458302ac2d004b9a0a638932cb41dfcf2980e731dc1e164e78755e54be305"
                    "f821130e25bfd8f9e423132f9984e587ff58aea0"
                ),
                b"",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-6-KE with external aad, default info, default hpke aad
            (
                HPKE_6_KE_KEY,
                (
                    "d8608443a10103a105582054037148342b2929d4126a1daa1a5cf49963f07f4bcfc6b125cc95"
                    "69315d428158212c12be5f1b14cb0be9cbc7f89e7d17cf6332f978ed3ff28e6ecf4177b43991"
                    "1f1f818353a2011834044d626f622d68706b655f365f6b65a1235838fe5677121bc5b939bd1f"
                    "3183d63ca7a1eb9834655073980f22463e0f4347c823ae7fbcb106311bfe1862b5d8fb09be30"
                    "222d73a1aec51a6d583092c3aeb223577ce70c4eb6d3fbdde2507ab0eb66684450f313a60987"
                    "82bc2b7042880301438d9d3b1a8f65b8103a611c"
                ),
                b"external-aad",
                b"",
                b"",
            ),
            # HPKE-6-KE with external aad, default info, external hpke aad
            (
                HPKE_6_KE_KEY,
                (
                    "d8608443a10103a10558204717640f13442de964fe2df975d1f5b9049338cdc799143725983f"
                    "3aac5e3bc45821c259895cb58581bcccb17204a6b99ea05cb1c556420025c4487f7df0d1a7ca"
                    "89db818353a2011834044d626f622d68706b655f365f6b65a123583835b83dad83bce401ecbc"
                    "78215d29c362be31727d86d14d1a983ee709f9cf23b44d1be7146c2ebab629d5e9d3a78e7ddc"
                    "3b2ae9490ffedb355830652b1c2e54232fd67da865383a4196b3081d6af8f3dce4cfb2cbf74c"
                    "b631df27c4180e081c4456df72e306b033871415"
                ),
                b"external-aad",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-6-KE with default aad, external info, default hpke aad
            (
                HPKE_6_KE_KEY,
                (
                    "d8608443a10103a1055820cf185363d088aa84b66d952d905d67801aac1692a51fd70c5198bf"
                    "ec655cc17958219df95a1b0832f6ba161f831da0511904d075628c42d88bd96c6d051edd67d7"
                    "082f818353a2011834044d626f622d68706b655f365f6b65a12358385148182fcb71312bda64"
                    "8d9a7a4c4dd74ae840a0f0617f2d4b89c834eaa55b4e9636334a53bb1821e0fa15c38590c75f"
                    "d2e09a5c678c6f0758306a9450456cd531a0b2d8215f7c6f67b8d8fee596d5093f9ae8e3d0fa"
                    "4d606c6b9c06fbe22cc186807e20816d411a3c8c"
                ),
                b"",
                b"external-info",
                b"",
            ),
            # HPKE-6-KE with default aad, external info, external hpke aad
            (
                HPKE_6_KE_KEY,
                (
                    "d8608443a10103a1055820561f96247e2ea00c85aac63bbeb1ee480f21ab3e9ebf2dfc54c324"
                    "e1440b8da158216ec7606341f7ca01b47a12f96b14b592a19acec35fc8575a14e77c1120f62a"
                    "9ace818353a2011834044d626f622d68706b655f365f6b65a1235838f60e9ef789715248f9f3"
                    "1fb9436aecee7a2fea8799fe436a97b5ad25b5dfbb697f9965e6f446e91fcffc3ff5e682fcb4"
                    "e7a4bffa596f0a395830dee903c258f9be6e9019e2663c97b5912bac14ec09f814b9501dcc29"
                    "c7211a60b0b15ecb21ea434c38dd8363d2783e3e"
                ),
                b"",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-6-KE with external aad, external info, default hpke aad
            (
                HPKE_6_KE_KEY,
                (
                    "d8608443a10103a1055820dc036988cb1a9f5c3c2ab7320fd3a38bacb9c23b034172c59fbeb0"
                    "26dc9f744658210c6ba63dfb087141b507a55070900ea3ae097aaacd3a400c83148f55e85134"
                    "032c818353a2011834044d626f622d68706b655f365f6b65a1235838bdc971ce40e3e124a014"
                    "5a622e1ec19182bfdc0cd66fbf8f6ff8fe7b43af1363c26be033563da00e96c8008f8804884d"
                    "ff825beacc89f63858305a3af658bcc81a615f025485efd9925e243d9d3331f0a0fd1a65fc6f"
                    "28a0895bc30eabac5cdb11e6cf82204d096e7489"
                ),
                b"external-aad",
                b"external-info",
                b"",
            ),
            # HPKE-6-KE with external aad, external info, external hpke aad
            (
                HPKE_6_KE_KEY,
                (
                    "d8608443a10103a10558209bedce93fc7ff55e06af978546a3b48e5a4c46caf3c1dcd70e1452"
                    "9d98c0278a582144091e536a28a763f4441b7432ea884c7ec2ac0b68e938c8de8c05c5009e82"
                    "d6e2818353a2011834044d626f622d68706b655f365f6b65a1235838ed5e7fdd82a824dc43c8"
                    "7a72f84943d3d7ea70331dc513ebaa11136fce401eee755106b7498ba2dcbf6180677b735796"
                    "bd9ed654c23ac2215830802d61870ffd823813b63c670db3319374b040e6de9a9b14015d2d2d"
                    "e1601f13ddfb6e054c78e4bb35127be2bb775803"
                ),
                b"external-aad",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-7-KE with default aad, default info, default hpke aad
            (
                HPKE_7_KE_KEY,
                (
                    "d8608443a10103a1055820b4ad67bdb6937286a5983cc45f54b41e3c7a0df82e12f1b7e7925b"
                    "de628eca6a582142b48f53df1fcc1caf84bc4820476082e55146a04e1726aabea65114de8329"
                    "bda5818353a2011835044d626f622d68706b655f375f6b65a12358410433c37c35e3c3c333af"
                    "f1bc62edfa2765518c7cd4e025a8b23ffb3fcf78f13d051cdb830d89f97e1567f27362420b63"
                    "d0cbc4c1dcf6df18f2c599e763c575c3f0583029ee7739a3699d79e1ffbb652f99741a1e2d15"
                    "cc05bf68d8a9f55bf3b77e33c22f5c7bdd3a842031325f385f6ed972c4"
                ),
                b"",
                b"",
                b"",
            ),
            # HPKE-7-KE with default aad, default info, external hpke aad
            (
                HPKE_7_KE_KEY,
                (
                    "d8608443a10103a10558208123621364280f31244476af7ba86971aee01f51ec197f63127acc"
                    "2845c1c23e5821f71f66a19a63bf08eeae9cab07ab5c8454816f7370a6c4f58630647a5988d5"
                    "b823818353a2011835044d626f622d68706b655f375f6b65a123584104ba669a6cdf24f9eb90"
                    "2c0647fa7011c764d210f10c4de956188b2137829b736b1d0ec5e6d71ca286d279391a4d129b"
                    "a3cd904edc3d61ee98cf45528b81e3f9db5830b2e8ad669f478914862185c6ec6f70593d29b8"
                    "e2ec523b7d89f9cd914ad34ca7752fe3629b4680c8466942adf7a14ac2"
                ),
                b"",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-7-KE with external aad, default info, default hpke aad
            (
                HPKE_7_KE_KEY,
                (
                    "d8608443a10103a105582073a819dcb519a63355b711e7ba4bd278a25a5065983b9490f0169c"
                    "3ca1a6c446582159ef651b16dd3eccb599906d27a3f3d06e09efeb0bae147f5cc3cd8ad87669"
                    "7401818353a2011835044d626f622d68706b655f375f6b65a1235841044fd069ae9dc9a02997"
                    "9615eddba8e946dc4087817c8e02680dce2b0415fa8839904afe73c3c045f32a010603ee158d"
                    "eb96e3c5a97c501fecf9b29b8914d4a71658304c694a5e09eecc922621d3dfe02b7e5dd0ff7c"
                    "174ad6001f24a0764867f8a3c18dad15a51d85542ef85b0753f4654cee"
                ),
                b"external-aad",
                b"",
                b"",
            ),
            # HPKE-7-KE with external aad, default info, external hpke aad
            (
                HPKE_7_KE_KEY,
                (
                    "d8608443a10103a1055820bd1930d292a90e8c717057f53fa6bf9058e0b9d3e6c013c6e19061"
                    "ad839a47cd58215bc9e46ef5be53dea520078ae2e41ccd5b9b5419f273b5dd8c35459184eb8a"
                    "8512818353a2011835044d626f622d68706b655f375f6b65a12358410438bd711f6e6cea92c0"
                    "008fa4b6e6874d6466ed63ae3031a87ed03d074b236f1b07526363c63f5d90ef5ee45a41e00f"
                    "726f3bf1c61a0de461f1da41545f055c255830795f8c1b78115df8af58f49b8f5fd94df744f5"
                    "0f6f36836cd15441dceb88c196d0a4014ac8ed81832a6a106dc974591f"
                ),
                b"external-aad",
                b"",
                b"external-hpke-aad",
            ),
            # HPKE-7-KE with default aad, external info, default hpke aad
            (
                HPKE_7_KE_KEY,
                (
                    "d8608443a10103a1055820921ada478a6296b81674ec480e27ff77ef0cc691967b235920c45b"
                    "e58079f1fb5821bc50d6b7348a33fac2aff9d9b289dce83c8a60050309fb6f432d564a6e6b90"
                    "9366818353a2011835044d626f622d68706b655f375f6b65a1235841046d92481c24059c5d5a"
                    "e998048868ac975a2d87136c62dd53fca5cce700f45c2c7da093dbf84545880f8f81fd51b9d7"
                    "3622153324ffe35ff80ab9edc828b6db945830f6c919e08dc6f0dddb0bec457ceb6726f5a3c1"
                    "8d97389d96d894b553e602f0d48449740735f900b1d6fd7e4003457ee8"
                ),
                b"",
                b"external-info",
                b"",
            ),
            # HPKE-7-KE with default aad, external info, external hpke aad
            (
                HPKE_7_KE_KEY,
                (
                    "d8608443a10103a105582003a092a86b3432027f1eff4e1cad509aa786f73a5148a17d0071b7"
                    "798a5b2206582153bbf01e70aaec7dfddea48b28dd511afadc6edc7524bbe449ac677c2136c9"
                    "94a5818353a2011835044d626f622d68706b655f375f6b65a12358410481bc8c8fd41e43207e"
                    "76e38a808c04c69ac716e4e95d712732df1bfacaf548039db70e5ec9374f6744eb88b8d4480d"
                    "e1caa03f6fb7a3c9ae7b60f7715e4bada858309d22782eedf0f851fa507b74fd05d1bd7d995e"
                    "15bbd5162ef0ab08840cda5b6b55a7ed79500990cefe94a8f312518bb0"
                ),
                b"",
                b"external-info",
                b"external-hpke-aad",
            ),
            # HPKE-7-KE with external aad, external info, default hpke aad
            (
                HPKE_7_KE_KEY,
                (
                    "d8608443a10103a10558208e23d1384869e09d81b29aca4a6c914f5b6e1fab76298600146e7b"
                    "82bcd3349558218784389faa384d51bb2488fa493d63f2e3fe72634c99944c5a8b7bb32e6ad4"
                    "b5fa818353a2011835044d626f622d68706b655f375f6b65a1235841041542669339ff82f8c6"
                    "4acb331de9103d339042bf8bd61d75056cd05d70d136c2b481b1dd2b220196228a1f4a8f7099"
                    "1176deb68ca4900a698878900cd3bf76395830f611c9c31785c2d7bcca2638da2375131fe228"
                    "7b72f4b4b93ba1d8424ba12fe6a48bb8ac5d0bad1cf7b8f81cf9d11bcc"
                ),
                b"external-aad",
                b"external-info",
                b"",
            ),
            # HPKE-7-KE with external aad, external info, external hpke aad
            (
                HPKE_7_KE_KEY,
                (
                    "d8608443a10103a10558200014fd43c613aaa6578d3001abeef3c028cb1c3079f21ff6da777a"
                    "9c586b985f5821333e109d32d4cb58224e3cc3958b0696233e4a824586fc953056b55fb0f988"
                    "f9e3818353a2011835044d626f622d68706b655f375f6b65a123584104cfd2686a4ab624d792"
                    "050d5fefd9f128467196fc437fccc02643ed770b1944502d9515c98bad76e6b4c3c982ea8192"
                    "124bc3dfd61901af0bd9676e5e189a93a15830334cdf07561053063f668bb025f4d46cbab520"
                    "2de419d34ce5e49290c886763b170fcc5586f9eec223a6a94ae484542c"
                ),
                b"external-aad",
                b"external-info",
                b"external-hpke-aad",
            ),
        ],
        ids=[
            "HPKE-0-KE-default-aad-default-info-default-hpke-aad",
            "HPKE-0-KE-default-aad-default-info-external-hpke-aad",
            "HPKE-0-KE-external-aad-default-info-default-hpke-aad",
            "HPKE-0-KE-external-aad-default-info-external-hpke-aad",
            "HPKE-0-KE-default-aad-external-info-default-hpke-aad",
            "HPKE-0-KE-default-aad-external-info-external-hpke-aad",
            "HPKE-0-KE-external-aad-external-info-default-hpke-aad",
            "HPKE-0-KE-external-aad-external-info-external-hpke-aad",
            "HPKE-1-KE-default-aad-default-info-default-hpke-aad",
            "HPKE-1-KE-default-aad-default-info-external-hpke-aad",
            "HPKE-1-KE-external-aad-default-info-default-hpke-aad",
            "HPKE-1-KE-external-aad-default-info-external-hpke-aad",
            "HPKE-1-KE-default-aad-external-info-default-hpke-aad",
            "HPKE-1-KE-default-aad-external-info-external-hpke-aad",
            "HPKE-1-KE-external-aad-external-info-default-hpke-aad",
            "HPKE-1-KE-external-aad-external-info-external-hpke-aad",
            "HPKE-2-KE-default-aad-default-info-default-hpke-aad",
            "HPKE-2-KE-default-aad-default-info-external-hpke-aad",
            "HPKE-2-KE-external-aad-default-info-default-hpke-aad",
            "HPKE-2-KE-external-aad-default-info-external-hpke-aad",
            "HPKE-2-KE-default-aad-external-info-default-hpke-aad",
            "HPKE-2-KE-default-aad-external-info-external-hpke-aad",
            "HPKE-2-KE-external-aad-external-info-default-hpke-aad",
            "HPKE-2-KE-external-aad-external-info-external-hpke-aad",
            "HPKE-3-KE-default-aad-default-info-default-hpke-aad",
            "HPKE-3-KE-default-aad-default-info-external-hpke-aad",
            "HPKE-3-KE-external-aad-default-info-default-hpke-aad",
            "HPKE-3-KE-external-aad-default-info-external-hpke-aad",
            "HPKE-3-KE-default-aad-external-info-default-hpke-aad",
            "HPKE-3-KE-default-aad-external-info-external-hpke-aad",
            "HPKE-3-KE-external-aad-external-info-default-hpke-aad",
            "HPKE-3-KE-external-aad-external-info-external-hpke-aad",
            "HPKE-4-KE-default-aad-default-info-default-hpke-aad",
            "HPKE-4-KE-default-aad-default-info-external-hpke-aad",
            "HPKE-4-KE-external-aad-default-info-default-hpke-aad",
            "HPKE-4-KE-external-aad-default-info-external-hpke-aad",
            "HPKE-4-KE-default-aad-external-info-default-hpke-aad",
            "HPKE-4-KE-default-aad-external-info-external-hpke-aad",
            "HPKE-4-KE-external-aad-external-info-default-hpke-aad",
            "HPKE-4-KE-external-aad-external-info-external-hpke-aad",
            "HPKE-5-KE-default-aad-default-info-default-hpke-aad",
            "HPKE-5-KE-default-aad-default-info-external-hpke-aad",
            "HPKE-5-KE-external-aad-default-info-default-hpke-aad",
            "HPKE-5-KE-external-aad-default-info-external-hpke-aad",
            "HPKE-5-KE-default-aad-external-info-default-hpke-aad",
            "HPKE-5-KE-default-aad-external-info-external-hpke-aad",
            "HPKE-5-KE-external-aad-external-info-default-hpke-aad",
            "HPKE-5-KE-external-aad-external-info-external-hpke-aad",
            "HPKE-6-KE-default-aad-default-info-default-hpke-aad",
            "HPKE-6-KE-default-aad-default-info-external-hpke-aad",
            "HPKE-6-KE-external-aad-default-info-default-hpke-aad",
            "HPKE-6-KE-external-aad-default-info-external-hpke-aad",
            "HPKE-6-KE-default-aad-external-info-default-hpke-aad",
            "HPKE-6-KE-default-aad-external-info-external-hpke-aad",
            "HPKE-6-KE-external-aad-external-info-default-hpke-aad",
            "HPKE-6-KE-external-aad-external-info-external-hpke-aad",
            "HPKE-7-KE-default-aad-default-info-default-hpke-aad",
            "HPKE-7-KE-default-aad-default-info-external-hpke-aad",
            "HPKE-7-KE-external-aad-default-info-default-hpke-aad",
            "HPKE-7-KE-external-aad-default-info-external-hpke-aad",
            "HPKE-7-KE-default-aad-external-info-default-hpke-aad",
            "HPKE-7-KE-default-aad-external-info-external-hpke-aad",
            "HPKE-7-KE-external-aad-external-info-default-hpke-aad",
            "HPKE-7-KE-external-aad-external-info-external-hpke-aad",
        ],
    )
    def test_ke_vector(self, key_hex, ct_hex, external_aad, extra_info, hpke_aad):
        key = COSEKey.new(cbor2.loads(bytes.fromhex(key_hex)))
        ct = bytes.fromhex(ct_hex)
        result = COSE.new().decode(ct, key, external_aad=external_aad, extra_info=extra_info, hpke_aad=hpke_aad)
        assert result == b"hpke test payload"


class TestCOSEHPKEEncrypt0Vectors:
    """Test vectors for COSE-HPKE Integrated Encryption (COSE_Encrypt0)."""

    @pytest.mark.parametrize(
        "key_hex, ct_hex, external_aad, hpke_info",
        [
            # HPKE-0 Encrypt0 with default aad and default info
            (
                HPKE_0_KEY,
                (
                    "d08344a1011823a2044e626f622d68706b655f302d696e7423584104bb6385b1cd5009597006"
                    "380ba2de0f66d293007755640f57b13a234bbe7241cf6f91f45469f85e99a13b9567257b7025"
                    "298bcf6e7f4c1f29ab5229381f4b99e65821ed584cb52cb3720135d1aed21adeca560e00effb"
                    "931cf17f9b60542abc92e80b63"
                ),
                b"",
                b"",
            ),
            # HPKE-0 Encrypt0 with external aad and default info
            (
                HPKE_0_KEY,
                (
                    "d08344a1011823a2044e626f622d68706b655f302d696e74235841040c483c4a0f7e41e98c58"
                    "5fdb19ab95789ec6f7f6fe3e7e4943e3e0ce147e42c0688808a3284f779bd374d2a83e72d024"
                    "8e3c6339a932cabb35c084071b75670a58218c9fd85ac5f111b2ef077872bcf72a7222a8ed8b"
                    "dcf6f4036f304eb03c75450067"
                ),
                b"external-aad",
                b"",
            ),
            # HPKE-0 Encrypt0 with default aad and external info
            (
                HPKE_0_KEY,
                (
                    "d08344a1011823a2044e626f622d68706b655f302d696e74235841048ab08975a473b7e85a87"
                    "96479a986b1d57270074ab819bbea2eb48a666c78fd4cfa1558f56dbde81848b19b1a2bf9a84"
                    "38dcf8e4a2d800bb155cbb6e9b41956e58217a8a794081022469dab987927fff8e642d7f2f44"
                    "b96eab7bb5b78b8fe7b5e6f2a5"
                ),
                b"",
                b"external-info",
            ),
            # HPKE-0 Encrypt0 with external aad and external info
            (
                HPKE_0_KEY,
                (
                    "d08344a1011823a2044e626f622d68706b655f302d696e74235841049d1716049cee3aa5f23d"
                    "2b3bbc96fd251262a97d3b0dbc53eac742b8c89fe887af7ab816ca8aee7abacacd1a2ab0495e"
                    "57aeff22611139d1cf894a666529b1615821590565fd461c31edbfb529c208c29b87c7c924b9"
                    "c570d8308cb006f1c86b646544"
                ),
                b"external-aad",
                b"external-info",
            ),
            # HPKE-1 Encrypt0 with default aad and default info
            (
                HPKE_1_KEY,
                (
                    "d08344a1011825a2044e626f622d68706b655f312d696e7423586104652d74d6ded632be58df"
                    "df81aeb3e7f365f86ad170c509dac27c2107551538c5b4ea89f36b6aa4315b39ec96528c7b0d"
                    "049f5c70d801e6d522e7a91f559b52eb2b706d93f3f11d1cfbd1906a5c4c3380150d46926c3f"
                    "469526389ecd0e1f9db6582144c5fd46930ccf302b5315faa3337d76c8622fe8ec6df824ad7e"
                    "376007d52e02ac"
                ),
                b"",
                b"",
            ),
            # HPKE-1 Encrypt0 with external aad and default info
            (
                HPKE_1_KEY,
                (
                    "d08344a1011825a2044e626f622d68706b655f312d696e7423586104106388d784f2cdaab13c"
                    "77b6f67d0229d552ce2e7707dc5a17ec01f74637d4275ad2a931ca7d0062f7bf45be096cc29b"
                    "7b2ba96efc974ce673c29d47a7a2db63eb0a5c55aa6c5abf9f728f7b4f29435437c59409584a"
                    "61cbcd4a83a1f876fe1c582174d9cbc04fd6fcc0ad6aa587a38f21be70e381f4b8de184c4e7e"
                    "3fffa246418ac6"
                ),
                b"external-aad",
                b"",
            ),
            # HPKE-1 Encrypt0 with default aad and external info
            (
                HPKE_1_KEY,
                (
                    "d08344a1011825a2044e626f622d68706b655f312d696e7423586104fdd2d7553bc31201851c"
                    "acb28ec135df4ba6f4cbc92362a18d3024ba3944a74ff46bad3cedca97215c8e5c337aee23a0"
                    "4bf42d777fc2a38e14ffb0337a983de8e6fdc28714b52718073333aa374bca263d1b270bb610"
                    "98be1032271cf5e166fd5821124c3c9acc6700f6faab0503ea8306ccafa6ad341e69017b5d57"
                    "877bba7c8d7c4c"
                ),
                b"",
                b"external-info",
            ),
            # HPKE-1 Encrypt0 with external aad and external info
            (
                HPKE_1_KEY,
                (
                    "d08344a1011825a2044e626f622d68706b655f312d696e74235861047a2c8b275dd48bba7666"
                    "452c6ee4db7e4d9c53790344b446223753d4fd6c15b6a513cf223af0935562820f9336396edd"
                    "5a096498dd7c49cd7dab87a86cfa03ef507bdfc3de2403569cf02bd702afd76c756d9aae114b"
                    "a4dc5b94ecd29f62d383582171c1a6219cf72d7446a59c00c5fa692d17c0efc3b92c34a2ff0c"
                    "c56adcea9b65e7"
                ),
                b"external-aad",
                b"external-info",
            ),
            # HPKE-2 Encrypt0 with default aad and default info
            (
                HPKE_2_KEY,
                (
                    "d08344a1011827a2044e626f622d68706b655f322d696e7423588504009a6b229af01086f3d2"
                    "69bc53e80af50c51fa34d7919137f7ee341773859909eb8a42d528d3cb4aa8d11e2b0456a1ee"
                    "a80b77a5ac960c22899e96bcd5a41b57277101eb8043867d62f64de2c6400d5239b17d5fc1c1"
                    "544eba22ee4c2f464fbb88a0b24d532b7587727cca8d93f5a39997a3cb9ef2490ea1d1fe46a4"
                    "5fa96fb2b26bf6ec582199e3fd2ccf2add11cd4be8ea6819e00af7b3a37d46e674ab6028376f"
                    "f99125ce2e"
                ),
                b"",
                b"",
            ),
            # HPKE-2 Encrypt0 with external aad and default info
            (
                HPKE_2_KEY,
                (
                    "d08344a1011827a2044e626f622d68706b655f322d696e7423588504008f1fbff7e1c3960d04"
                    "ed74bdd86b19c995af96468008b7ad62e9ca2d060c222fda6bd30831e04fe797b6a87f7b0eb3"
                    "25a2b0b0e5331d302aaf69aa386ec9276fa901dc4056f6331d58093273ed605c1e1e32b2e368"
                    "afe71390246f8fa20d7ffc6e790a06d86e588f658bb0bee30c523101b351433ea1c611cd0d2f"
                    "df6e924fce55eed2582120bb19765d3444e43325d1c8a7d4a510c4a85a88cf3b9a2763e477f9"
                    "e064e08510"
                ),
                b"external-aad",
                b"",
            ),
            # HPKE-2 Encrypt0 with default aad and external info
            (
                HPKE_2_KEY,
                (
                    "d08344a1011827a2044e626f622d68706b655f322d696e7423588504006dba8c9caad42c743a"
                    "ebca073875e1e5780c828162072850df9a8c83975f64dc4466152a8bbd12d7bef79c00a589a0"
                    "b8bced83b8fa82fbc1a50a33e0a54a1420ae010b5dd6dcc9bd0baf5101485f37d011fdd902da"
                    "d39843343bb57be244e566047a60d54a15ec9c8d25d91b97ea7be7a1ae118898ec8c273d8819"
                    "8ba4d0f5e74ec14b58218e160a01123c22b9a4f4859a9d101bdad6ce576c6cc68343ec54f32f"
                    "644facdba2"
                ),
                b"",
                b"external-info",
            ),
            # HPKE-2 Encrypt0 with external aad and external info
            (
                HPKE_2_KEY,
                (
                    "d08344a1011827a2044e626f622d68706b655f322d696e74235885040100fffac417f1ddde4c"
                    "2f9316e7031d73aeb7e21e2223da751c310971d8d78861fe437facaad58c2a72abc8ffd5c9c0"
                    "52ce345c7dd7a871204f8d90669bc8a3679f016ef52865c7bc9a221dc67c1a9c12405943772a"
                    "7db4658c8855b80b6883812ba92017f8fb98bf9bad12ac14a7e2eaea2c7fb3a9513e117ccf69"
                    "c3e6998abd0e3e2a5821657d17e9ca01ee51f7a88a870ac0719e2c1ae8d0881e6e9c03ffb483"
                    "4d586aa98a"
                ),
                b"external-aad",
                b"external-info",
            ),
            # HPKE-3 Encrypt0 with default aad and default info
            (
                HPKE_3_KEY,
                (
                    "d08344a1011829a2044e626f622d68706b655f332d696e742358200a97fc27b9542a666479ad"
                    "6635d9d5988e2bb187db4f8b3b48f60f2d06bac46b5821f058dcbad9bad8553fd6cbccfd5048"
                    "6e33dd96557d5805c6327af6624760bc7a1b"
                ),
                b"",
                b"",
            ),
            # HPKE-3 Encrypt0 with external aad and default info
            (
                HPKE_3_KEY,
                (
                    "d08344a1011829a2044e626f622d68706b655f332d696e7423582093a055592c2978fe4c7424"
                    "e649938700ead043668b0a12c4233350f7927a250958216ec61f83f6fab279d636bbc78bccaf"
                    "9d06d34b9f39b0d615b26066c1c584fc05e4"
                ),
                b"external-aad",
                b"",
            ),
            # HPKE-3 Encrypt0 with default aad and external info
            (
                HPKE_3_KEY,
                (
                    "d08344a1011829a2044e626f622d68706b655f332d696e74235820b9a5e203033c7c5d15bce2"
                    "c35cd59e24db38db2114b9c5d16edc5d7ec4cfb54f5821807a3046ee8c725701d5e9bf547277"
                    "2e84b5a2cffbd4b296d55af264da8b14b87e"
                ),
                b"",
                b"external-info",
            ),
            # HPKE-3 Encrypt0 with external aad and external info
            (
                HPKE_3_KEY,
                (
                    "d08344a1011829a2044e626f622d68706b655f332d696e742358201d6124b3462a25d3ed374b"
                    "88a4702afa7831aafd81af5c8774eceef569f0234658210fcbc960c3f6a049cbff49d881fff0"
                    "0a86152cfbbeccdeec111fdadc848665b9f0"
                ),
                b"external-aad",
                b"external-info",
            ),
            # HPKE-4 Encrypt0 with default aad and default info
            (
                HPKE_4_KEY,
                (
                    "d08344a101182aa2044e626f622d68706b655f342d696e7423582081cbeefeef0b8a8b736f70"
                    "0fe52ff25f0cfc7302e5075a44b95e7cf5a82a96775821e5c0ebf3de1016b0fd33f41c0774d6"
                    "b283dd494537c729ad7decab64bd5c1f43e5"
                ),
                b"",
                b"",
            ),
            # HPKE-4 Encrypt0 with external aad and default info
            (
                HPKE_4_KEY,
                (
                    "d08344a101182aa2044e626f622d68706b655f342d696e742358204c41250100e5f505dd0acf"
                    "8830ff1d22e7954d8f6d88d59c809c95d903849c4658218c99cbbe71f8f695e6e79dc6f41279"
                    "3c3ea9d1464066e2d08aaa27b5fef24ec144"
                ),
                b"external-aad",
                b"",
            ),
            # HPKE-4 Encrypt0 with default aad and external info
            (
                HPKE_4_KEY,
                (
                    "d08344a101182aa2044e626f622d68706b655f342d696e7423582004aa6884ce80e188a0ef54"
                    "96c24f6798afde8c8dc623bc2654ce836bb2b9be4158211bc91f4db16f81fdab012e74c00ae5"
                    "353eb258e433b8ea4b28893d7436fe7615f2"
                ),
                b"",
                b"external-info",
            ),
            # HPKE-4 Encrypt0 with external aad and external info
            (
                HPKE_4_KEY,
                (
                    "d08344a101182aa2044e626f622d68706b655f342d696e74235820bcf1e847f43e3f4244751c"
                    "e5e4ac782fc5270310590a3cf8fb825e5ad6be54145821e9c1313608956f65a12558a94ce3fa"
                    "04ec84ecdeb2eed4eee2a4fbbe783cfcfdd7"
                ),
                b"external-aad",
                b"external-info",
            ),
            # HPKE-5 Encrypt0 with default aad and default info
            (
                HPKE_5_KEY,
                (
                    "d08344a101182ba2044e626f622d68706b655f352d696e742358388f5af58e1f0db443f7404b"
                    "1ede00a32b977cd3a699b46928f5c571c306deed1f2d859381c0b6b6f666a78514b5041fb2e7"
                    "f694d5692598ec58216a365c1bdcac86157cbacf68ac46d89597440a775607af455e754d42f9"
                    "8b197336"
                ),
                b"",
                b"",
            ),
            # HPKE-5 Encrypt0 with external aad and default info
            (
                HPKE_5_KEY,
                (
                    "d08344a101182ba2044e626f622d68706b655f352d696e74235838981878c54475dc1e97661a"
                    "bdb4189c05b5063564297b3e6ac252412720eaf098cf854555ac700035374a0cba8abc3bdcb7"
                    "0e42d202f55410582139fece2ab3dd76bb900ebec9c8436ff8b4e129499e10c703fce9099b96"
                    "2a2baf2e"
                ),
                b"external-aad",
                b"",
            ),
            # HPKE-5 Encrypt0 with default aad and external info
            (
                HPKE_5_KEY,
                (
                    "d08344a101182ba2044e626f622d68706b655f352d696e74235838cfc56e2a7bc6e0968b29a1"
                    "3c995a2f1d6c14096facae8f6c4de89e5f59baf0c25dd5547034c2cb157b275b0f7dc74837b6"
                    "5f4092bc6bbfbf582162df9346e36efb8d4a3b55dff58ab2095a31b5de9973dd51f9c8859902"
                    "566c345d"
                ),
                b"",
                b"external-info",
            ),
            # HPKE-5 Encrypt0 with external aad and external info
            (
                HPKE_5_KEY,
                (
                    "d08344a101182ba2044e626f622d68706b655f352d696e74235838e7bfbb375d9d1ec703b833"
                    "3d50f5bb62e5a8ebe093e207cc7f65b102f03706bce492b83be7d86b61c00863e96edff00888"
                    "dad9ba39e60143582112636db0edaa6c58de1b9029084a0dfb8c26b09f3e7bd8d0f962a1e8ba"
                    "c74f71cc"
                ),
                b"external-aad",
                b"external-info",
            ),
            # HPKE-6 Encrypt0 with default aad and default info
            (
                HPKE_6_KEY,
                (
                    "d08344a101182ca2044e626f622d68706b655f362d696e7423583805b7dc9742e800cda70b5b"
                    "f55e2cfafb1414b630dca621999897a223c6564295328f4d913deff488d7a5ac70b089679e80"
                    "8b1b9ecf18e43458217bba22205a379a6af9cbc37dc608d0571ca8f0146e4ddbe0bcacb5ffc2"
                    "59a3325f"
                ),
                b"",
                b"",
            ),
            # HPKE-6 Encrypt0 with external aad and default info
            (
                HPKE_6_KEY,
                (
                    "d08344a101182ca2044e626f622d68706b655f362d696e742358385b964c5c2e9a12226b649c"
                    "eaf964a4e50a8fe428fb288756c59cb92bd03d4c0eaa8c2104907cb8fe7487c14e4ef7ce11f3"
                    "9cd4d1f1b209d1582151c6acdfdc65920d6d047a7d47acdab642493698a89444c5f32e688804"
                    "7611c48b"
                ),
                b"external-aad",
                b"",
            ),
            # HPKE-6 Encrypt0 with default aad and external info
            (
                HPKE_6_KEY,
                (
                    "d08344a101182ca2044e626f622d68706b655f362d696e74235838f601104f62360338e92952"
                    "7dba71011acc9ea59ec3fe3fb5cc338a3ce03b75664111ac030a6260091a80a4926447010c97"
                    "b6079bd6cd33b75821fb8851b4c848830717589eedf46fc7dcd23af1de491a4c2273918bb78e"
                    "7d8e232c"
                ),
                b"",
                b"external-info",
            ),
            # HPKE-6 Encrypt0 with external aad and external info
            (
                HPKE_6_KEY,
                (
                    "d08344a101182ca2044e626f622d68706b655f362d696e7423583869e66f4b70a1306856a7f0"
                    "9e5d8b41fb808786c30a54e1627f2f65c33ce66212f0c2e5bf769391b7fd7d691f1dfe7c8b13"
                    "1793e9727314f658216df8f6658779fc5f234cd58e6049f6795524f9ba00549772ca617d6262"
                    "b230b81d"
                ),
                b"external-aad",
                b"external-info",
            ),
            # HPKE-7 Encrypt0 with default aad and default info
            (
                HPKE_7_KEY,
                (
                    "d08344a101182da2044e626f622d68706b655f372d696e74235841040ae250a36575d60ebcd5"
                    "0444d99d1f1546438585fc807338d0a69cffad14d45b28047e5e4d7429f628e9f83130585353"
                    "75dcf1ce1804a83b8745b2d63064cf6b5821847f648fbeb8e38689248933366fe6929e36843d"
                    "7855e318c48383f54022b7bac7"
                ),
                b"",
                b"",
            ),
            # HPKE-7 Encrypt0 with external aad and default info
            (
                HPKE_7_KEY,
                (
                    "d08344a101182da2044e626f622d68706b655f372d696e74235841046a563d7eea744ccbacc9"
                    "ea6df50e002d8b235fabc7023d51c75e5ba22af4102c1c20954d6cc1b2b63f893d504301c94f"
                    "c37ba89084d04ca59f96581d87435f215821d619e5c0189533c39c353cab4db8a939225c170e"
                    "840915b27503b9de88f5451beb"
                ),
                b"external-aad",
                b"",
            ),
            # HPKE-7 Encrypt0 with default aad and external info
            (
                HPKE_7_KEY,
                (
                    "d08344a101182da2044e626f622d68706b655f372d696e7423584104e5f56b98441f710117e3"
                    "d9019b5d09cde61b1d4f228353062b8a7667aa58dab2e511b922f740eb7b8850a5a838bcb6c1"
                    "6ddc1cb6d7000e7d2e2d69867e11d73a582107834d1f44591c01db20acb0d7f71faa793e11f7"
                    "c83619a9410a97991eef3a56eb"
                ),
                b"",
                b"external-info",
            ),
            # HPKE-7 Encrypt0 with external aad and external info
            (
                HPKE_7_KEY,
                (
                    "d08344a101182da2044e626f622d68706b655f372d696e742358410472587451cdc65749b672"
                    "4a78484c69e4a7092edec45c31aaf13a1b725b388820efb2b381bab4b52efeb9d6d65ff69c49"
                    "b765426a6a4fd7872b3691149069394a582142a32c0ba176b2053b114682189982e07506a4ac"
                    "383067aa9920552e452be123b8"
                ),
                b"external-aad",
                b"external-info",
            ),
        ],
        ids=[
            "HPKE-0-Encrypt0-default-aad-default-info",
            "HPKE-0-Encrypt0-external-aad-default-info",
            "HPKE-0-Encrypt0-default-aad-external-info",
            "HPKE-0-Encrypt0-external-aad-external-info",
            "HPKE-1-Encrypt0-default-aad-default-info",
            "HPKE-1-Encrypt0-external-aad-default-info",
            "HPKE-1-Encrypt0-default-aad-external-info",
            "HPKE-1-Encrypt0-external-aad-external-info",
            "HPKE-2-Encrypt0-default-aad-default-info",
            "HPKE-2-Encrypt0-external-aad-default-info",
            "HPKE-2-Encrypt0-default-aad-external-info",
            "HPKE-2-Encrypt0-external-aad-external-info",
            "HPKE-3-Encrypt0-default-aad-default-info",
            "HPKE-3-Encrypt0-external-aad-default-info",
            "HPKE-3-Encrypt0-default-aad-external-info",
            "HPKE-3-Encrypt0-external-aad-external-info",
            "HPKE-4-Encrypt0-default-aad-default-info",
            "HPKE-4-Encrypt0-external-aad-default-info",
            "HPKE-4-Encrypt0-default-aad-external-info",
            "HPKE-4-Encrypt0-external-aad-external-info",
            "HPKE-5-Encrypt0-default-aad-default-info",
            "HPKE-5-Encrypt0-external-aad-default-info",
            "HPKE-5-Encrypt0-default-aad-external-info",
            "HPKE-5-Encrypt0-external-aad-external-info",
            "HPKE-6-Encrypt0-default-aad-default-info",
            "HPKE-6-Encrypt0-external-aad-default-info",
            "HPKE-6-Encrypt0-default-aad-external-info",
            "HPKE-6-Encrypt0-external-aad-external-info",
            "HPKE-7-Encrypt0-default-aad-default-info",
            "HPKE-7-Encrypt0-external-aad-default-info",
            "HPKE-7-Encrypt0-default-aad-external-info",
            "HPKE-7-Encrypt0-external-aad-external-info",
        ],
    )
    def test_encrypt0_vector(self, key_hex, ct_hex, external_aad, hpke_info):
        key = COSEKey.new(cbor2.loads(bytes.fromhex(key_hex)))
        ct = bytes.fromhex(ct_hex)
        result = COSE.new().decode(ct, key, external_aad=external_aad, hpke_info=hpke_info)
        assert result == b"hpke test payload"
