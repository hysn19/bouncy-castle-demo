package com.raonsecure.server;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Hello world!
 *
 */
public class App {

    public static void main(String[] args) throws Exception {
        RSAEncrypt();
        // ECCEncrypt();
    }

    public static void RSAEncrypt() throws Exception {

        String text = "RSA encryption and decryption test";

        RSAEncryptUtil util = new RSAEncryptUtil();

        KeyPair pair = util.generateKey();
        PrivateKey priKey = pair.getPrivate();
        PublicKey pubKey = pair.getPublic();

        System.out.println("pub=" + byteArrayToHex(pair.getPublic().getEncoded()));
        System.out.println("pri=" + byteArrayToHex(pair.getPrivate().getEncoded()));

        // byte[] priKeyBytes = hexToByteArray(
        // "308204a30201000282010100a12fc1c0be1f67aa3cc14aff9b2f8cb3686d2007f2638e413bc4b49f2e0fefeb65a0fe5fe0109660ddb1bda26df7eddd5f3d5da3d074ba2b6eb8bf67dead9ba1719ea82540e5f6ee8ef562425045259a7dd0e9939e39e55e54d432351f6ff3b9b4951b90423a79cb815953c778eec5d0df7a193e637467fab5054f027dddc031bac392fa5b99091bf80f74cc2f430a32abfb5f2bde97f4640f2cc83eb1711e9a7bdc2bff196e0a8f3689ffca01f159c4fcc686986819b5a404b96aafed2af59069533fd1dc1d59f382d4d1a6a4347570bafd56a05f863f6c327c3f7203292d6ac249b7b709849fca5a4eeaf1844ef7d0e2406b72702bf31d59a309c22724bb6702030100010282010003c4cbc1479b665f70478e0b07443259a8dc66fe533d89559f21cc9e02d95e8bb6219b30ff5a83eeef3563b0b38f88cbe9ee7e62567d1433f06fce11e353fdd53ad9dc7befd630a8329c2c2da41629cdeb43d78cf0607c2b70ccfc00dff8f722e56fadbda4141d4593d854817a78b814028051577318855732fa5521981dcce0e8938a87e38c634443a6833e221edb03d9a3f9af02d05e73bd3499fa090f7e47a247d009dbb43c1361373ebf20cd9a3e9321f931fcd91a328e53eb8cb0df4ee2222242c4e8aeeda40bd9685132babf1e7428d3d85788584be9518ef95a6a9d90d335ea0707bafe83a5396aa066349a39ee2283f04e678a40649815de2f4b264102818100dfb5ba2e5d43c5c401445935911e864709d7f50e39fc53b640a5c7a71553e0432cc09da9b2b96a245a4fe2f91e16ba2a5c10a19a0530fd59fcd6e0ea1e62b5e0e4cc9f97a186eff0c9a537599b446d13d8a475ad16994f11c9694384d8cc8a4376f7a813c880605d3435d53fc7e28a272abf51ebd267a06d168837bff830490702818100b873bd28c1dd6589ee32edd0dce7cace2d0df9d99eb2789ef07f02280f3ed290048596da6da6af848a262eaf70d8b8db62dc43c831b898f01e14ada5371640e487bee3313e3c08811c2e12439da298653f2206583d9e0e8c9829ef3e844dd3c06b544df661b3a0296b6b7912c6006e938c53b388c95749665566ecce24b542a102818100a5aff7cbfd2183e8eeb34b8b440722969cb0c8fc17704e23eeef99d6a31233482d6e1f979f1a7a85a02a08c64f45afee4dafb7b0d665794f5bd75e4fa7df9e2b89ea0fcd8341e8962312edd2bd0fc9e5e80fae645b17831b7e5c2b38ca457ba60a07d50189ffa2df851ad5ed5e42e7e5a86078f13b2dab0100ae34f44682a4a30281804e8bdacd7460d7507942eecab6876e7185f621a36e5509d0851150d5c648365a65d28d7ece9ae0bb4c291e504f79ba9e91e6c26689e5d61aca747bcd933bc2be8e9fd717ad2cdb623fa1cedd444f6d1e105868e342b9fff0170c247936d5fd8a3f2a5358cc1a35e5ed7c82be5fdae73ba5d22eeddcef72ae4547e32795b22a810281807082d3de2a2fbba10dd87e1f3e596a6fc5cc5972c7abba485315b66ad3ffe7295a02e522580d0e54c5414b49ba5f697a5d15627a05e782f18a70fcb0b847627bcac92dd588ce83a48e11eb6338f6edd7d36a84ce1ed826d05b33dbafac97e9e3489ce44c7a69a053bde4b44887b69844fc4059cfd84d9323a609224887fd3d8f");
        // byte[] pubKeyBytes = hexToByteArray(
        // "30819f300d06092a864886f70d010101050003818d0030818902818100e941eb043129395ca6b4908d0ab8d047984e3a4996763da75ab11914b5c99d94ae3ddc9c13fa53eedc452a742d8565819dba7127b9dd519357b3e53eb0bc5286979d3808b2958f81346da03ad87d091de0e2650bc318100c0ea2e1f936fa9848f6a845579368d532a5640e090cb7f3977e94f525031b3b225ac5b3c1d033e0930203010001");
        // KeyFactory kf = KeyFactory.getInstance("RSA",
        // BouncyCastleProvider.PROVIDER_NAME);
        // PrivateKey priKey = kf.generatePrivate(new PKCS8EncodedKeySpec(priKeyBytes));
        // PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

        byte[] cipher = util.encrypt(text.getBytes("UTF-8"), pubKey);
        System.out.println("cipher=" + byteArrayToHex(cipher));

        byte[] plain = util.decrypt(cipher, priKey);
        System.out.println("plain=" + new String(plain));

    }

    public static void ECCEncrypt() throws Exception {

        String text = "ECC encryption and decryption test";

        ECCEncryptUtil util = new ECCEncryptUtil();

        KeyPair pair = util.generateKey();
        PrivateKey priKey = pair.getPrivate();
        PublicKey pubKey = pair.getPublic();

        System.out.println("pub=" + byteArrayToHex(pair.getPublic().getEncoded()));
        System.out.println("pri=" + byteArrayToHex(pair.getPrivate().getEncoded()));

        byte[] cipher = util.encrypt(text.getBytes("UTF-8"), pubKey);
        System.out.println("cipher=" + byteArrayToHex(cipher));

        byte[] plain = util.decrypt(cipher, priKey);
        System.out.println("plain=" + new String(plain));
        
    }

    public static byte[] hexToByteArray(String hex) {
        if (hex == null || hex.length() == 0)
            return null;

        byte[] ba = new byte[hex.length() / 2];

        for (int i = 0; i < ba.length; i++)
            ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);

        return ba;
    }

    public static String byteArrayToHex(byte[] ba) {
        if (ba == null || ba.length == 0)
            return null;

        StringBuffer sb = new StringBuffer(ba.length * 2);
        String hexNumber;

        for (int x = 0; x < ba.length; x++) {
            hexNumber = "0" + Integer.toHexString(0xff & ba[x]);
            sb.append(hexNumber.substring(hexNumber.length() - 2));
        }

        return sb.toString();
    }
}
