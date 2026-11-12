from cgrophy import Sha1

SHA1_MONTE_CARLO = {
    "seed": bytes.fromhex("dd4df644eaf3d85bace2b21accaa22b28821f5cd"),
    "expected": {
        0: bytes.fromhex("11f5c38b4479d4ad55cb69fadf62de0b036d5163"),
        1: bytes.fromhex("5c26de848c21586bec36995809cb02d3677423d9"),
        2: bytes.fromhex("453b5fcf263d01c891d7897d4013990f7c1fb0ab"),
        3: bytes.fromhex("36d0273ae363f992bbc313aa4ff602e95c207be3"),
        4: bytes.fromhex("d1c65e9ac55727fbf30eaf5f00cc22b9bab81a2c"),
        5: bytes.fromhex("2c477cd77e5749da7fc4e5ca7eed77166e8ceae6"),
        6: bytes.fromhex("60b11211137f46863501a32a435976eabd4532f3"),
        7: bytes.fromhex("0894f4f012a1e5344044e0ecfa6f078382064602"),
        8: bytes.fromhex("06b6222855cae9bed77e9e3050d164a98286ea5f"),
        9: bytes.fromhex("e2872694d3d23a68a24419c35bd9ac9006248a8f"),
        10: bytes.fromhex("ea43595eb1cff3a7e045c5868d0775b4409b14a3"),
        11: bytes.fromhex("05a9e94fdc792a61aa60bcd37592acee1f983280"),
        12: bytes.fromhex("7d11aa9413cd89a387a5c0f9aa5ce541be2aa6e8"),
        13: bytes.fromhex("37297d053aaa4a845cc9ce0c0165644ab8d0e00b"),
        14: bytes.fromhex("d9dcde396d69748c1fe357f8b662a27ce89082c8"),
        15: bytes.fromhex("737a484499b6858b14e656c328979e8aa56b0a43"),
        16: bytes.fromhex("4e9c8b3bce910432ac2ad17d51e6b9ec4f92c1ad"),
        17: bytes.fromhex("62325b9a7cebcc6da3bfe781d84eb53a6eb7b019"),
        18: bytes.fromhex("4710670e071609d470f7d628d8ea978dfb9234ac"),
        19: bytes.fromhex("23baee80eee052f3263ac26dd12ea6504a5bd234"),
        20: bytes.fromhex("9451efb9c9586a403747acfa3ec74d359bb9d7ff"),
        21: bytes.fromhex("37e9d7c81b79f090c8e05848050936c64a1bd662"),
        22: bytes.fromhex("a6489ff37141f7a86dd978f685fdd4789d1993dc"),
        23: bytes.fromhex("39650d32501dfcee212d0de10af9db47e4e5af65"),
        24: bytes.fromhex("cd4ea3474e046b281da5a4bf69fd873ef8d568d6"),
        25: bytes.fromhex("0d7b518c07c6da877eee35301a99c7563f1840df"),
        26: bytes.fromhex("68a70ae466532f7f61af138889c0d3f9670f3590"),
        27: bytes.fromhex("c0222aae5fd2b9eff143ac93c4493abe5c8806af"),
        28: bytes.fromhex("d2efc5aa0b29db15f3e5de82aaa0a8ce888ffb2f"),
        29: bytes.fromhex("eec4f55d02c627dcee36b5b5606603bdc9a94a26"),
        30: bytes.fromhex("0e706fb1a1fa26aab74efcef57ab6a49c07ca7bd"),
        31: bytes.fromhex("2ea392ca8043686424f7e9500edfb9e9297943f7"),
        32: bytes.fromhex("74737ef257b32a4cb9428c866b65bee62ccbe653"),
        33: bytes.fromhex("df3e86e49a0429fa81f553b04b9fc003510e9a51"),
        34: bytes.fromhex("79c3049944fbf8b80dadadc7f5174e5cfdf996de"),
        35: bytes.fromhex("f25e2eca4cfb6da8e8b7b62f581672fab80754fa"),
        36: bytes.fromhex("76509239d9fd6c6f050c0d9b3777b5645e4d4c70"),
        37: bytes.fromhex("cf4bb3e1f330c862e239d9b010bd842f302bd227"),
        38: bytes.fromhex("4eeac7ab2ac9e4c81ed1a93a300b2af75beddb08"),
        39: bytes.fromhex("46443ba72a64fff4b5252fbac9ef93c2949f8585"),
        40: bytes.fromhex("5e9c42482343a54aadb11ab00c2e00cbe25ec91a"),
        41: bytes.fromhex("93acee1977128f2a4218678b32e2844f23eb526b"),
        42: bytes.fromhex("226065d299b2d6c582d386897b93f2adf14de00b"),
        43: bytes.fromhex("672fed0d90c21d4ec0111a7284bcf1bbd72af9bd"),
        44: bytes.fromhex("90d642f12f28cb3dad7daad84cf0f94ded1137ae"),
        45: bytes.fromhex("4a2815b58ffc858e5e7e9e6106765458d2af4ec3"),
        46: bytes.fromhex("29fa3679032421b78b7a08c54766c1592f6739c1"),
        47: bytes.fromhex("19f4e30393eb66c6e200744fa8999d224e6df173"),
        48: bytes.fromhex("30650026be77212088ab50438e04b4b8e3761977"),
        49: bytes.fromhex("993d0e135bcd598fa673c6f19251bcbde18b7b34"),
        50: bytes.fromhex("c9eaf20b473219a70efe85940620426c6ff6f4a4"),
        51: bytes.fromhex("6325d0b83c308bd42854ce69446e85ba36348d7d"),
        52: bytes.fromhex("2fb354f8a68030efb747f78812060a9c05e92164"),
        53: bytes.fromhex("a7e33bd16f770c17e8818ad5a5fc4fee673eae56"),
        54: bytes.fromhex("ff23e7105bc9f4dad0fb9c6519d1eae16439a5d6"),
        55: bytes.fromhex("a31aca821e163213cd2ae84cf56c1134daa4a621"),
        56: bytes.fromhex("94ab9cfd4cf9bf2e4409dbcdc9ef2c8b611cc69d"),
        57: bytes.fromhex("c0194064ce48dde771b7871efa86a4a6e87eec76"),
        58: bytes.fromhex("f1a9065e3e7f98753c6f833f5ffe74133f6b887f"),
        59: bytes.fromhex("b8b3cd6ca1d5b5610e43212f8df75211aaddcf96"),
        60: bytes.fromhex("33c3a8d739cc2f83be597aa11c43e2ad6f0d2436"),
        61: bytes.fromhex("4f5c67e5110f3663b7aa88759dbba6fa82f2d705"),
        62: bytes.fromhex("b1ebc87c7b2b8fe73e7a882d3f4f0492946e0d7c"),
        63: bytes.fromhex("01566616fe4a8c7cf22f21031ac6ea7fb7ce15db"),
        64: bytes.fromhex("5650f3517a393792781d23b4c9d360bf8bd31d65"),
        65: bytes.fromhex("a4fdbd24cb4a328b898b804b103caa98baedd3fa"),
        66: bytes.fromhex("0cf01eecec4b85aa39f40aa9b4dce208d68eb17b"),
        67: bytes.fromhex("ae9ac147bab7c10609abe6e931a5ab087a41dc5a"),
        68: bytes.fromhex("c0328145ce63fb0aceeb414e791d2be92009b1ec"),
        69: bytes.fromhex("60343e5fb7eee00d31ea507b820ddbb7ef405dc7"),
        70: bytes.fromhex("e0b97cd9149ff9955b6a35b3a79ecb3bdbd2a5a5"),
        71: bytes.fromhex("4e4fdcd382ae0f3f4fbda5fd934eee0d6ad37df5"),
        72: bytes.fromhex("9d97dd237d193482cf3ab862a38843762e69077f"),
        73: bytes.fromhex("2bc927d17ff2f8a844f6f36a944a64d73d431192"),
        74: bytes.fromhex("b91200306b769aab18e5e411b5bd5e7bce1cc80e"),
        75: bytes.fromhex("c47493a666085e1b7a75618761a80c402f46546d"),
        76: bytes.fromhex("31355869b80ff84fac239db694ada07d3be26b15"),
        77: bytes.fromhex("1a2022f6330bf96f025cb7d8f0201a7d70b3b58e"),
        78: bytes.fromhex("0f60d7c5ad49efce939c3a27da9973f7f1747848"),
        79: bytes.fromhex("ceada087801616fc6c08cfa469658f3dc5239ca7"),
        80: bytes.fromhex("4ad0cf9181122b06df714397bd5366aa90bfc9fa"),
        81: bytes.fromhex("ac6404e6b9d5c0fa17fa77fd39850f22b76ecd83"),
        82: bytes.fromhex("f0658218adffb9ee9328577854b6387393957a3a"),
        83: bytes.fromhex("6fe9992747897389957b9a91467a4ec983829ab6"),
        84: bytes.fromhex("74320b3ddde6dbfbdad3ad29a7695f5a275b2105"),
        85: bytes.fromhex("2009ea5d6452f51d12477740e374e0e313134779"),
        86: bytes.fromhex("7dbf33d7125709f101fea4ec03436ab95a900c28"),
        87: bytes.fromhex("0c05b78e324cb265bd6adc7452249eaa85bccb3f"),
        88: bytes.fromhex("10c1b9b2de8a9050fb6f4b10a99f7e1e47159f25"),
        89: bytes.fromhex("20072c1f691142d9b83a090dd01f446b4e325a1c"),
        90: bytes.fromhex("ffcb6a1525f20803cfc79deb40addfd3e7b2f05c"),
        91: bytes.fromhex("bdcbb4ed636e244bb0fe6af4bc53998936df4ebc"),
        92: bytes.fromhex("f58ccbc65a2ffa5b35274dd0ceb4ea70eb73c26a"),
        93: bytes.fromhex("fbe95ac75e4b9cccd1a5debf757fa1a502d07944"),
        94: bytes.fromhex("a8babac55950dba4993601d35adff874a2b9bb2a"),
        95: bytes.fromhex("594db79de71c7651e9eef2f08bb7be3d26b6ee99"),
        96: bytes.fromhex("63377d45d0e2d0c987bebe8086c76a5e8b63a14b"),
        97: bytes.fromhex("cd1e7a192130866aa87fd1c8b43e9b7a0eab7615"),
        98: bytes.fromhex("b3c69ad5dbdd34b7b45b2a89dad72f4cf1d8fd73"),
        99: bytes.fromhex("01b7be5b70ef64843a03fdbb3b247a6278d2cbe1"),
    },
}

def test_empty_str():
    m = Sha1()
    m.update(b"")
    expected = bytes([
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
        0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
    ])

    assert m.digest() == expected

def test_abc():
    m = Sha1()
    m.update(b"abc")
    expected = bytes([
        0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
        0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
        0x9C, 0xD0, 0xD8, 0x9D
    ])
    assert m.digest() == expected

def test_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq():
    m = Sha1()
    m.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    expected = bytes([
        0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1
    ])
    assert m.digest() == expected

def test_1_million_a():
    m = Sha1()
    m.update(("a" * 1_000_000).encode())
    expected = bytes([
        0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E, 0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F
    ])
    assert m.digest() == expected

"""
SHAVS Monte-Carlo Test: https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/shs/shavs.pdf
"""
def test_monte_carlo_simulation():
    seed = SHA1_MONTE_CARLO["seed"]
    for count in range(100):
        state = [seed] * 4
        for i in range(1000):
            x = Sha1()
            m = state[(i+1)&3] + state[(i+2)&3] + state[(i+3)&3]
            x.update(m)
            seed = state[(i&3)] = x.digest()
        assert SHA1_MONTE_CARLO["expected"][count] == seed

