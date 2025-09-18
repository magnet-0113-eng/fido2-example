from base64 import urlsafe_b64decode, urlsafe_b64encode
import json
import cbor2
import hashlib
import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def decode(str):
    str = str + '=' * (-len(str)%4)
    return urlsafe_b64decode(str)

def jwk(pk):
    if pk[3] == -7:
        pkjwk = {
            'kty': 'EC',
            'crv': 'P-256',
            'x': urlsafe_b64encode(pk[-2]).decode(),
            'y': urlsafe_b64encode(pk[-3]).decode(),
        };
    elif pk[3] == -257:
        pkjwk = {
            'kty': 'RSA',
            'n': urlsafe_b64encode(pk[-1]).decode(),
            'e': urlsafe_b64encode(pk[-2]).decode(),
        };
    else:
        raise ValueError('Non algorithm.');

    return pkjwk;

def aaguid(id):
    return id[0:8] + '-' + id[8:12] + '-' + id[12:16] + '-' + id[16:]

def regist(attestationObject):
    attestation = cbor2.loads(decode(attestationObject))

    print(attestation)

#    challenge = urlsafe_b64encode(bytearray('my_challenge', encoding='utf-16le'))
#    print("{}".format(challenge))

    # rpIdHash
    print("rpIdHash: {}".format(attestation['authData'][0:32].hex()))
#    print(hashlib.sha256(b'localhost').hexdigest())

    # flags
    flags = attestation['authData'][32]
    print("flags: {}".format(flags))
    print(bool(flags & 0x01)) # UP == true
    print(bool(flags & 0x04)) # UV == true
    print(bool(flags & 0x08)) # BE == true
    print(bool(flags & 0x10)) # BS == true
    print(bool(flags & 0x40)) # AT == true
    print(bool(flags & 0x80)) # ED == true

    # signCount
    signCount = attestation['authData'][33] << 24 | attestation['authData'][34] << 16 | attestation['authData'][35] << 8 | attestation['authData'][36]
    print("signCount: {}".format(signCount))

    # aaguid
    print("aaguid: {}".format(aaguid(attestation['authData'][37:53].hex())))

    credentialIdLength = (attestation['authData'][53] << 8) + attestation['authData'][54]
    credentialId = attestation['authData'][55:55+credentialIdLength]
    credentialPublicKey = attestation['authData'][55+credentialIdLength:]

    print(len(credentialId))
    print(credentialId.hex())
    print(len(credentialPublicKey))
    print(cbor2.loads(credentialPublicKey))
    print(jwk(cbor2.loads(credentialPublicKey)))

    print(attestation['fmt'])
    if attestation['fmt'] == 'packed':
        if 'x5c' in attestation['attStmt']:
            signature = attestation['attStmt']['sig']
            attestnCert = attestation['attStmt']['x5c'][0]

            cert = x509.load_der_x509_certificate(attestnCert, default_backend())
#            print(cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME))

            pn = cert.public_key().public_numbers()
            message = attestation['authData']

            try:
                print(pn.x)
                print(pn.y)

                ec.EllipticCurvePublicNumbers(pn.x, pn.y, ec.SECP256R1()) \
                .public_key(default_backend()) \
                .verify(signature, message, ec.ECDSA(hashes.SHA256()))
            except:
                return {"error": "Invalid Signature"}

    '''
    id, jwk(credentialPublicKey), signCount を保存
    '''
    saveData = {
        'jwk': jwk(cbor2.loads(credentialPublicKey)),
        'count': signCount,
        'time': time.time(),
    }

    # hex(rawId)
    print(saveData)

    with open('/tmp/hogehoge.json', mode='w') as f:
        f.write(json.dumps(saveData))

    return saveData

def auth(authenticatorData):
    print("call auth")
    print(authenticatorData)

    authenticator = decode(authenticatorData)

    print(authenticator)

    # rdIdHash
    print("rpIdHash: {}".format(authenticator[0:32].hex()))

    # flags
    flags = authenticator[32]
    print("flags: {}".format(flags))
    print(bool(flags & 0x01)) # UP == true
    print(bool(flags & 0x04)) # UV == true

    # signCount
    signCount = authenticator[33] << 24 | authenticator[34] << 16 | authenticator[35] << 8 | authenticator[36]
    print("signCount: {}".format(signCount))
    print(authenticator[33])
    print(authenticator[34])
    print(authenticator[35])
    print(authenticator[36])

    # saveData を取ってくる
    with open('/tmp/hogehoge.json') as f:
        loadData = json.loads(f.read())

    print(loadData)

    try:
        # kty == EC の場合の処理
        x = decode(loadData['jwk']['x'])
        y = decode(loadData['jwk']['y'])

        x = int(x.hex(), 16)
        y = int(y.hex(), 16)

        '''
        crv == 'P-256': ec.SECP256R1()
        crv == 'P-384': ec.SECP384R1()
        crv == 'P-521': ec.SECP521R1()
        '''
    except:
        return {"error": "Invalid Signature"}

    print("checkCount: {} > {}".format(signCount, loadData['count']))
    if signCount <= loadData['count']:
        return {"error": "Invalid Sign Count"}

    # カウンターを進めるて保存
    loadData['count'] = signCount
    with open('/tmp/hogehoge.json', mode='w') as f:
        f.write(json.dumps(loadData))

    # 認証処理

    return {
        "text":"OK",
        "user":"hogehoge",
        "session":"******",
    }

if __name__ == "__main__":
    print("\nmac chrome\n")
    data = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFEyBKLqDquaZPs0ZvtATs2DlmsuPpQECAyYgASFYIKEtHDKI92n144ZeuJhVa64-dgp8tfClPfwqnmCukeDyIlggGbTPEqzlHOTiM8MXd4-orjGObdYjQxvaURhrAoyS0ks"
    regist(data)

    print("\nios mypm\n")
    data = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVik4IRbxDfJvMMpCYRaKlNcTJ1od6qAZma0i/KWKviQ+mvdAAAAAAAAAAEAAQABAAECAwQFBgcAIAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABpQECAyYgASFYIHPDDetJIxks6E+nm2WBPwkGZ5WtbZQ/PQH1E23dM3l4IlggQqjKoqvOmjyYDBP2BHGPCJWYeUwE0HEJv4eUouUGiJA="
    regist(data)
