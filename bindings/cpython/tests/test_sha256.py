from cgrophy.hash import Sha256

SHA256_MONTE_CARLO = {
    "seed": bytes.fromhex("6d1e72ad03ddeb5de891e572e2396f8da015d899ef0e79503152d6010a3fe691"),
    "expected": {
        0: bytes.fromhex("e93c330ae5447738c8aa85d71a6c80f2a58381d05872d26bdd39f1fcd4f2b788"),
        1: bytes.fromhex("2e78f8c8772ea7c9331d41ed3f9cdf27d8f514a99342ee766ee3b8b0d0b121c0"),
        2: bytes.fromhex("d6a23dff1b7f2eddc1a212f8a218397523a799b07386a30692fd6fe9d2bf0944"),
        3: bytes.fromhex("fb0099a964fad5a88cf12952f2991ce256a4ac3049f3d389c3b9e6c00e585db4"),
        4: bytes.fromhex("f9eba2a4cf6263826beaf6150057849eb975a9513c0b76ecad0f1c19ebbad89b"),
        5: bytes.fromhex("3ddf05ba8dfec982451a3e9a97695ea9cdb7098c877d0c2cd2c64e58a87754d9"),
        6: bytes.fromhex("2cc3fe501e3b2e33e60407b0a27025735dd04fd7623bb4fceeebae5cad67ad4b"),
        7: bytes.fromhex("c534802a459b40c792e1fa68e54ceab69e333fbeeecad65fb124d2f3cc1f1fc1"),
        8: bytes.fromhex("8986e95d85e64822287c78cb7a714339431332182107109d57827776c6cc930e"),
        9: bytes.fromhex("72361401c670d07f1151a95e2ee914665c2bdb1228581833c7dc53b89c01c927"),
        10: bytes.fromhex("124c443bad9d955e084a3961b079c43c59b5e0d666af38f2f37846e85369a618"),
        11: bytes.fromhex("81914b78674a2a6204eef78ff51369526bf0c2e121cd364eb40a8435479dda14"),
        12: bytes.fromhex("8eac9d963b44021b70a527ea07420b03f51a998d0d6cb73ad4cb7fc688b4d174"),
        13: bytes.fromhex("0427263b4dd3ebfcb7871939dbaca5ca94e794f748c02920c9759dfa554ea534"),
        14: bytes.fromhex("3e9d754f2ec273b0056c2fcad2e891aaf9616fe74005d36cbf5ccba2e037b5b3"),
        15: bytes.fromhex("986b6594ed96a819e49edb9f65db2ea52168973d7e18ae9e0b8869a8b5dd29a0"),
        16: bytes.fromhex("117578126a35176a00f8c0cf999442df0890737be1880f06e6a7270959c114c6"),
        17: bytes.fromhex("fd7f5574788d8ef64b83333ffb62e4cd3311e638db0c514071c19b84e9117afe"),
        18: bytes.fromhex("19db7ba6e3488a9e935af33ffb912d60c9d3b98a0be1d78e0b374dcb5274a7fb"),
        19: bytes.fromhex("52519e6319505df7a9aa83778618ec10b78c5771bac50e8d3f59bc815dabfb1f"),
        20: bytes.fromhex("434d7795fc7510af04b613e120f7f48e6d613ec056ae9fbc7c869b87c1dce63e"),
        21: bytes.fromhex("020324de7f6763be57bc4a6a0960258ea401ffe40d68f854e82ccfa9e0612ff7"),
        22: bytes.fromhex("b87c7fd0ec4cd35fab077b64d00917ad06aaccb095bbe4603466644ce6cbce18"),
        23: bytes.fromhex("01abbd12b2b476b2d540d0c47edcb56263ea658a8080a8f08dbb313942562f00"),
        24: bytes.fromhex("ce95bb2bf2d5c91402e13ed5271615607f39e0678aae776d18a78351b90b5838"),
        25: bytes.fromhex("b81af264b0bb485f6656be91478f7b96c324fe262fcc366d9ce3edd44ccb85d0"),
        26: bytes.fromhex("9e2ad901200ca524c91373f7b5eda9cda142353e763862e350314f793a0b700d"),
        27: bytes.fromhex("dbfabc7124338d6845f083cb1bbdf7b4060274d8e0e98d08bb7ca3779059b45b"),
        28: bytes.fromhex("d93c2cd61f5476ea08d85f741720ab2ce5c4e38cd8254758238155fd68ea7723"),
        29: bytes.fromhex("232d9c3b583e297439c859150738e1b1d530812d63a9a2c1cb8e40cb50a2f27b"),
        30: bytes.fromhex("8b9c858bd135138d9023a0b5fcf3f12ebbc3b7f721ee0b44be1871187f21f506"),
        31: bytes.fromhex("05cedbd568ce9adcf5022999b8f3a28995a910c572375186da5febd775d62b79"),
        32: bytes.fromhex("24282cba8f5dfce7e423a103488a9a924080d549853c699159d27816dbdbe5d9"),
        33: bytes.fromhex("ba6e3c38128f93f288e781af8a13e7ce5120c2a43a6d1c0d4edc831247350079"),
        34: bytes.fromhex("706fffec5b69f5ef5465b6a8663c302143af743c6b7cd5fec9f3fa9bf9b2e285"),
        35: bytes.fromhex("6d32c55c005eea65dacdf0e90f436943d0d0acec3c2355c36e2df1a86d1a11a7"),
        36: bytes.fromhex("b353f425293db464ad814177ea9689f43054bcdbaf75675e918b78a82ca97a50"),
        37: bytes.fromhex("c3fa9993130b3c95d9aed30243ba902035933d18adf5e21d2567674769062e81"),
        38: bytes.fromhex("1e77e07988ebd618740c2f89a7bcf0ae2542279ea8895b39aa70ba8bc37ee00f"),
        39: bytes.fromhex("063927892a0b095be7d21987ff8157cd4c674c1cd01ab9f0834824e8efbcf938"),
        40: bytes.fromhex("f43054c280f05371cfbac776d43d6001f71350d898677f035aa8f7e5bd7b3fa3"),
        41: bytes.fromhex("2427934b28c7a9c2b18a5b7e996351aa567523744f60d54dc35bbb61f56f6fd4"),
        42: bytes.fromhex("3633976d174279161e13b49e5866c144ce8c1d17ec1901ad56a02c900273fe11"),
        43: bytes.fromhex("5f9788660d82c80155a7fea91896be3be2eb6a7b2ce963f3804cd09da5ac0c8f"),
        44: bytes.fromhex("097ef57de6df98c29346e67e7f676569ad402f7a1c88d1cf39ce2d44fd706f72"),
        45: bytes.fromhex("fedcc810c74706a27fc0b6663ab2f9de0761089682dff1279fcd91312af1b8e3"),
        46: bytes.fromhex("bd5d61fea8d23089f3f30266b1daa636a352e49476526e71cc0735cbd17054fe"),
        47: bytes.fromhex("5ead027c03d7a55c17f0c783b6d77670cdb8942772077d09dff9a46ecd527bec"),
        48: bytes.fromhex("7a06eeea07ca9eb94a98a5e9f00b7efd8de9843b6aa888822c3dccf803637732"),
        49: bytes.fromhex("44b6a895058ed3f31a5549407af8f788631f8a6eb8c0a5f2e15facc9190b5672"),
        50: bytes.fromhex("f8a58bff4b54aaebe18fc3f0bb1d24974a125530756dd4a0f15628c35c02ea1c"),
        51: bytes.fromhex("3bf2ae5408399aba59f42e5bed35a00d038fada16013ffa5da9e8b7207f6012c"),
        52: bytes.fromhex("31d33c0275986b06f6dccf570d1064c7b36e1574cc4371d4bba2e55321d75397"),
        53: bytes.fromhex("bda59cbd65e87a57df3f03c89e4d9511de71da05e2eee0560948696b37615f8f"),
        54: bytes.fromhex("f431cc1817569e92c8ba11ec4741e6dd2e361156575af7b482587ed78e9fb7fe"),
        55: bytes.fromhex("1b3b3789a32165f725167da6f5ef89d95de5992783961440fce67b66c3351ea6"),
        56: bytes.fromhex("c9873a09c079ca7f477b5601519ce51896c2a35a28fe05fe8b13e990813c6634"),
        57: bytes.fromhex("fb16cc865ddcf513be298c7d514033ab3fae7a80b285d2b43e82363342e498f4"),
        58: bytes.fromhex("ebaebc261b327f8be24026e32099a6b15927c54dbe390b72756f3f6362ea3b3a"),
        59: bytes.fromhex("ae5a4fdc779d808ba898966c8c14a6c9894107ef3e1d680f6ae37e95cb7e1b67"),
        60: bytes.fromhex("5a4a67451c197b038c540878b6e7bc6fce3eea9c95795d611359703d6cc7ca02"),
        61: bytes.fromhex("efb075aa051070a6b2303e026f81a5262a6e64eabb270ec5e13fc6efa3529f6f"),
        62: bytes.fromhex("8ff3df1a5cd0840bce61520f1e5645ce272a37b884c1750c69a957134c1a20d2"),
        63: bytes.fromhex("8fbd86567c20dc3ea9948dd5ea6f5204028c4ba258c35052994e7c86de2d7701"),
        64: bytes.fromhex("670559572a74e9af0513a3f9243bfbfd5805b837705faedc3c480d67a92bc124"),
        65: bytes.fromhex("ef2ad8656fac9c593d301fcfac77a7815d50b42526d3a44e1573316a25b05904"),
        66: bytes.fromhex("a3484a7a6cb5c941e15346a3ac4e09e99a5189cc96a87104d196af3c43cf995e"),
        67: bytes.fromhex("966851a0ef41f8d8ff970f4340a8dae8eec4f1999f5fd4f6cbcfa372fbf85495"),
        68: bytes.fromhex("8e1559cd4431febfa15662a2ccf2cac82f5401b2657551480bb0e3dd2111032c"),
        69: bytes.fromhex("5f535e2e7351cb8caf0070166218238a843c17472cea2f5911008be5d7fd6ba2"),
        70: bytes.fromhex("86ac4ea15f10c264b158058f5c13a36a87ac72f840071bbc45399b36823a5709"),
        71: bytes.fromhex("5c0d3fe289b2aac7d1bbaf57f4154b8d10875cffc9d8bd2402255ed1615f1d5f"),
        72: bytes.fromhex("d7d808366d0c8b76ce3e7ab80ea11b4e2f8758f9ff404a3aafbf5b0cc191adcb"),
        73: bytes.fromhex("e0768536856d1d7399667d6fd2c32f72416eeea1c40a313ee6edc910a5c3b786"),
        74: bytes.fromhex("d670923731b3e598f5c4db4c7e57fe2275cc6c49b4bf67cb91d520846aec256e"),
        75: bytes.fromhex("2cb0bdcc305ef3b3d6b7265ab62bee555c524102679da122424713a9a01d69f6"),
        76: bytes.fromhex("5acdc323fe067a4b915ee521ac8eb81bcff4e205d53e4e7f9a69d436035cc5ad"),
        77: bytes.fromhex("e634c43558d12c2a8710f2d6f10a86411cfad5a014e6b6cc159733c8ccece283"),
        78: bytes.fromhex("4a05f4bc3fcaf50e6d0916d7e7024b0ed22e9a3c413ff4bbcc0922d2326dcf6e"),
        79: bytes.fromhex("17c9d6029e15d3fd84e6809c5ef8a279a040f49ada91601a3ba4572cef7c08bd"),
        80: bytes.fromhex("1f21e137da2427536758409f3fbf5842589c5f587f0b9d2d10430f840faaaf45"),
        81: bytes.fromhex("e3d38cff8a8d7fc00693dca5e37b03e7b10dafe4926023e26d937106ddac6a78"),
        82: bytes.fromhex("cd749eb05c67038fe837910310b3b4cdda190f6235fa970602f865bec1b61a1b"),
        83: bytes.fromhex("d596ccddea01b4ae29b68b0e8a191007f0c89a1016c380b49786f2d4fac4c43d"),
        84: bytes.fromhex("cbccb1ff23e33c59dc4c858093c9e215c3759acfe6bc84ff75940b59b25a4e40"),
        85: bytes.fromhex("7214c134e9a963d6c43969d3ef44ece825dd9cf35bda5fcce92a6b9d0d3fd1b8"),
        86: bytes.fromhex("aceaf5b775779621319f9ab5d4d370a3359cd6553ed2328cdc9dbab5b68840fa"),
        87: bytes.fromhex("e8123acb0a2fb62978d3811b31676975542993932108ab14d487ad7875ddef72"),
        88: bytes.fromhex("660202a436fb05c3d59be699734e77c9750c906c8597ca213d064853ecf8c9f3"),
        89: bytes.fromhex("4752b0a5ec3f1fb295d5bfa98fa63a0ba38a02a4c1e1f73b0c4d4e88a07e0317"),
        90: bytes.fromhex("1e24f1467c36b051af3241fcf8c2c868b86dcb8e4669931878018e9914129b42"),
        91: bytes.fromhex("d1c3efc99d9487e147282d811ab932d4a24362d09ac909f4854e783887068891"),
        92: bytes.fromhex("7dc455cf6f8b2042b6f0f368c44f18a080e5d3912ce3cdaf7142bd61ae50d02e"),
        93: bytes.fromhex("4b991c15789084eb1d6c1d7ce8f0928df4d3931c0c22c571f375849b9a6c2b71"),
        94: bytes.fromhex("8b78f95a007cfb0bd054a1f5d962cd8d927665f79a5ce9e0fc31105e57b8460b"),
        95: bytes.fromhex("bf305423849cf773fc54206d8ae3c000c3e8b359cba8364581d1f91b0a201032"),
        96: bytes.fromhex("47006af96cff3843d3ed53bdedb167490d7bfefd93ae3e9ef473cb53aa840fc0"),
        97: bytes.fromhex("c53cf5026162021fd2345dbad7c53d3a3df47b5bdff8cd34a0ccfee06dbb7328"),
        98: bytes.fromhex("3326899b575f93cdaff757f8ab7c3996a2fe930450d5002d4575f4e4cc4b4360"),
        99: bytes.fromhex("6a912ba4188391a78e6f13d88ed2d14e13afce9db6f7dcbf4a48c24f3db02778"),
    },
}

def test_abc():
    m = Sha256()
    m.update(b"abc")
    expected = bytes([
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    ])
    assert m.digest() == expected

def test_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq():
    m = Sha256()
    m.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    expected = bytes([
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    ])
    assert m.digest() == expected

def test_1_million_a():
    m = Sha256()
    m.update(("a" * 1_000_000).encode())
    expected = bytes([
        0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
    ])
    assert m.digest() == expected

"""
SHAVS Monte-Carlo Test: https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/shs/shavs.pdf
"""
def test_monte_carlo_simulation():
    seed = SHA256_MONTE_CARLO["seed"]
    for count in range(100):
        state = [seed] * 4
        for i in range(1000):
            x = Sha256()
            m = state[(i+1)&3] + state[(i+2)&3] + state[(i+3)&3]
            x.update(m)
            seed = state[(i&3)] = x.digest()
        assert SHA256_MONTE_CARLO["expected"][count] == seed

