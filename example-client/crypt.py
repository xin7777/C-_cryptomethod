from M2Crypto import RSA,BIO

def readPEM():
    fp = file('pubkey.pem','rb');
    pub_key_str = fp.read();
    fp.close();

    mb = BIO.MemoryBuffer(pub_key_str);
    pub_key = RSA.load_pub_key_bio(mb);

    data = '12345678';
    en_data = pub_key.public_encrypt(data,RSA.pkcs1_padding);
    print(en_data)

readPEM()
