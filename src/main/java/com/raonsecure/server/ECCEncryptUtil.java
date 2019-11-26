package com.raonsecure.server;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * <p>
 * Title: ECCEncryptUtil
 * </p>
 * <p>
 * Description: Utility class that helps encrypt and decrypt strings using ECC
 * algorithm
 * </p>
 * 
 * @author jckim
 * @version 1.0
 */
public class ECCEncryptUtil {
    protected static final String ALGORITHM = "ECIES";
    protected static final String CURVE = "secp256k1";

    public ECCEncryptUtil() {
        init();
    }

    /**
     * Init java security to add BouncyCastle as an RSA provider
     */
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generate key which contains a pair of privae and public key using 1024 bytes
     * 
     * @return key pair
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    public KeyPair generateKey()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(new ECGenParameterSpec(CURVE)); // EC curve selection
        KeyPair key = keyGen.generateKeyPair();
        return key;
    }

    /**
     * Encrypt a text using public key.
     * 
     * @param text The original unencrypted text
     * @param key  The public key
     * @return Encrypted text
     * @throws java.lang.Exception
     */
    public byte[] encrypt(byte[] text, PublicKey key) throws Exception {
        byte[] cipherText = null;

        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text);
        return cipherText;
    }

    /**
     * Decrypt text using private key
     * 
     * @param text The encrypted text
     * @param key  The private key
     * @return The unencrypted text
     * @throws java.lang.Exception
     */
    public byte[] decrypt(byte[] text, PrivateKey key) throws Exception {
        byte[] dectyptedText = null;
        // decrypt the text using the private key
        Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, key);
        dectyptedText = cipher.doFinal(text);
        return dectyptedText;

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