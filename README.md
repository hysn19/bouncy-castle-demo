# bouncy-castle-demo
BouncyCastle Demo Java Project

RSA암복호화 및 ECC암복화 테스트를 위한 자바프로젝트

## RSAEncryptUtil Method

```java
RSAEncryptUtil util = new RSAEncryptUtil();

KeyPair pair = util.generateKey();
PrivateKey priKey = pair.getPrivate();
PublicKey pubKey = pair.getPublic();

byte[] cipher = util.encrypt(text.getBytes("UTF-8"), pubKey);
byte[] plain = util.decrypt(cipher, priKey);
```

## ECCEncryptUtil Method

```java
ECCEncryptUtil util = new ECCEncryptUtil();

KeyPair pair = util.generateKey();
PrivateKey priKey = pair.getPrivate();
PublicKey pubKey = pair.getPublic();

byte[] cipher = util.encrypt(text.getBytes("UTF-8"), pubKey);
byte[] plain = util.decrypt(cipher, priKey);
```
