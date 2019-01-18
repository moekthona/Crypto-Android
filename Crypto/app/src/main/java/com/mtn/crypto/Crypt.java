package com.mtn.crypto;

import android.util.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Formatter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypt {
    public static Crypt crypt = new Crypt();
    private String HASH_ALGORITHM = "HmacSHA256";

    public Crypt() {
    }

    public static Crypt shared(){
        return crypt;
    }

    public String encrypt(String key,String iv,String plaintext) throws Exception {

        IvParameterSpec ivp = generateIV(iv);
        SecretKeySpec keySpec = generateKey(key);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,keySpec,ivp);
        byte [] encValue  = cipher.doFinal(plaintext.getBytes());
        String encryptedvalue  = Base64.encodeToString(encValue,Base64.DEFAULT);

        return encryptedvalue;
    }


    public String decrypt(String key,String iv,String encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        IvParameterSpec ivp = generateIV(iv);
        SecretKeySpec keySpec = generateKey(key);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,keySpec,ivp);
        byte [] decode = Base64.decode(encrypted,Base64.DEFAULT);
        byte [] decyptorcode = cipher.doFinal(decode);

        return new String (decyptorcode);
    }

    public SecretKeySpec generateKey(String key) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(key.getBytes());

        SecretKeySpec secretKeySpec = new SecretKeySpec(md.digest(),"AES");

        return secretKeySpec;
    }

    public IvParameterSpec generateIV(String iv) throws NoSuchAlgorithmException{

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(iv.getBytes());

        IvParameterSpec ivParameterSpec = new IvParameterSpec(md.digest());
        return ivParameterSpec;
    }


    public String hash256(String text, String secretKey)
            throws SignatureException {

        try {
            Key sk = new SecretKeySpec(secretKey.getBytes(), HASH_ALGORITHM);
            Mac mac = Mac.getInstance(sk.getAlgorithm());
            mac.init(sk);
            final byte[] hmac = mac.doFinal(text.getBytes());
            return toHexString(hmac);
        } catch (NoSuchAlgorithmException e1) {
            // throw an exception or pick a different encryption method
            throw new SignatureException(
                    "error building signature, no such algorithm in device "
                            + HASH_ALGORITHM);
        } catch (InvalidKeyException e) {
            throw new SignatureException(
                    "error building signature, invalid key " + HASH_ALGORITHM);
        }
    }

    private  String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);

        Formatter formatter = new Formatter(sb);
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return sb.toString();
    }
}
