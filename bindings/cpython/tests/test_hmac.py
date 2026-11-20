from cgrophy.hmac import Hmac, SHA1, SHA256


def test_hmac_sha1_test_keysize_equals_blocksize():
    data = bytes.fromhex('53616d706c65206d65737361676520666F72206B65796C656E3D626C6F636B6C656E')
    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F')
    expected = bytes.fromhex('5FD596EE78D5553C8FF4E72D266DFD192366DA29')

    m = Hmac(key=key, hash_func=SHA1)
    m.update(data)
    digest = m.digest()

    assert expected == digest

def test_hmac_sha1_test_keysize_lt_blocksize():
    data = bytes.fromhex('53616d706c65206d65737361676520666F72206B65796C656E3C626C6F636B6C656E')
    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F10111213')
    expected = bytes.fromhex('4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807')

    m = Hmac(key=key, hash_func=SHA1)
    m.update(data)
    digest = m.digest()

    assert expected == digest

def test_hmac_sha1_test_keysize_gt_blocksize():
    data = bytes.fromhex('53616d706c65206d65737361676520666F72206B65796C656E3D626C6F636B6C656E')
    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263')
    expected = bytes.fromhex('2D51B2F7750E410584662E38F133435F4C4FD42A')

    m = Hmac(key=key, hash_func=SHA1)
    m.update(data)
    digest = m.digest()

    assert expected == digest

def test_hmac_sha1_test_keysize_lt_blocklen_truncated_tag():
    data = bytes.fromhex('53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E2C2077697468207472756E636174656420746167')
    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30')
    expected = bytes.fromhex('FE3529565CD8E28C5FA79EAC')

    m = Hmac(key=key, hash_func=SHA1)
    m.update(data)
    digest = m.digest()

    assert expected == digest

# HMAC SHA256
def test_hmac_sha256_test_keysize_equals_blocksize():
    data = bytes.fromhex('53616d706c65206d65737361676520666F72206B65796C656E3D626C6F636B6C656E')
    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F')
    expected = bytes.fromhex('8BB9A1DB9806F20DF7F77B82138C7914D174D59E13DC4D0169C9057B133E1D62')

    m = Hmac(key=key, hash_func=SHA256)
    m.update(data)
    digest = m.digest()

    assert expected == digest

def test_hmac_sha256_test_keysize_lt_blocksize():
    data = bytes.fromhex('53616d706c65206d65737361676520666F72206B65796C656E3C626C6F636B6C656E')
    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')

    expected = bytes.fromhex('A28CF43130EE696A98F14A37678B56BCFCBDD9E5CF69717FECF5480F0EBDF790')

    m = Hmac(key=key, hash_func=SHA256)
    m.update(data)
    digest = m.digest()

    assert expected == digest

def test_hmac_sha256_test_keysize_gt_blocksize():
    data = bytes.fromhex('53616d706c65206d65737361676520666F72206B65796C656E3D626C6F636B6C656E')
    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263')
    expected = bytes.fromhex('BDCCB6C72DDEADB500AE768386CB38CC41C63DBB0878DDB9C7A38A431B78378D')

    m = Hmac(key=key, hash_func=SHA256)
    m.update(data)
    digest = m.digest()

    assert expected == digest

def test_hmac_sha256_test_keysize_lt_blocklen_truncated_tag():
    data = bytes.fromhex('53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E2C2077697468207472756E636174656420746167')
    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30')
    expected = bytes.fromhex('27A8B157839EFEAC98DF070B331D5936')

    m = Hmac(key=key, hash_func=SHA256)
    m.update(data)
    digest = m.digest()

    assert expected == digest
