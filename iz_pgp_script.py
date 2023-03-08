from pgpy import constants, PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm



report = 'P,20230301,20230301,2.1'


def encrypt_pgp():
    # type: (str, str, Optional[Environment]) -> bytes
    
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    
    pkeystr = str(key.pubkey)
    pkey = key.pubkey
    
    print('public PGP key: ', pkeystr)
    
    cipher = constants.SymmetricKeyAlgorithm.AES256
    sessionkey = cipher.gen_key()

    encrypted_report = PGPMessage.new(report)

    encrypted_report = pkey.encrypt(encrypted_report, cipher=cipher, sessionkey=sessionkey)
    print('Encrypted:', encrypted_report)
     
    test_decrypted_report = key.decrypt(encrypted_report).message
    print('decrypt test: ', test_decrypted_report)
    
    with open('/Users/igor.zincenko/GIT/scripts/testFile.txt', 'wb') as local_fp:
        local_fp.write(bytes(encrypted_report))
    
    with open('/Users/igor.zincenko/GIT/scripts/testFile2.txt', 'wb') as remote_file:
        with open('/Users/igor.zincenko/GIT/scripts/testFile.txt', 'rb') as input_file:
            input_file.read()
            remote_file.write(input_file.read())
                
    return bytes(encrypted_report)


print('Encrypted response:', encrypt_pgp())
