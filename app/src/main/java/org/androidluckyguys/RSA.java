package org.androidluckyguys;

import org.springframework.util.Base64Utils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by LuckyRana on 12/09/2017.
 */

public class RSA {

    public static BigInteger publicModulus;
    public static BigInteger publicExponent;

    public static BigInteger privateModulus;
    public static BigInteger privateExponent;


    /*  Generationg Rsa key public and private modulus and exponetial and saving them
    *  i am saving them here as static variable
    *  for future refrence you can also save them anywhere else you like*/
    public void generateAndSaveRsaKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024); // you can decrease and increase this as per requirement
        KeyPair kp = kpg.genKeyPair();
        Key publicKey = kp.getPublic();
        Key privateKey = kp.getPrivate();

        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = fact.getKeySpec(publicKey,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec priv = fact.getKeySpec(privateKey,
                RSAPrivateKeySpec.class);

        publicModulus = pub.getModulus();
        publicExponent = pub.getPublicExponent();
        privateModulus = priv.getModulus();
        privateExponent = priv.getPrivateExponent();

    }


    public PublicKey readPublicKey() throws IOException {

        try {

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(publicModulus, publicExponent);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey pubKey = fact.generatePublic(keySpec);
            return pubKey;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
    }

    public PrivateKey readPrivateKey() throws IOException {

        try {

            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(privateModulus, privateExponent);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey priKey = fact.generatePrivate(keySpec);
            return priKey;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
    }

    public String rsaEncrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PublicKey pubKey = readPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherData = cipher.doFinal(data.getBytes());
        return Base64Utils.encodeToString(cipherData);
    }

    public String rsaDecrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PrivateKey pubKey = readPrivateKey();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] cipherData = cipher.doFinal(Base64Utils.decodeFromString(data));
        return new String(cipherData);
    }
}
