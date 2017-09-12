package org.androidluckyguys;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    String key = "MyEncryptionKey";  // change or create randomly as per your requirement
    /* sample data format */
    String name = "Lucky";
    String email = "Luckyrana321@gmail.com";
    String addresss = "xyz";

    String data = String.format("{\"Name\":\"%s\", \"Email\":\"%s\", \"Addresss\":\"%s\"}",name,email,addresss);


    TextView aesEncryptTv,aesDecryptTv,rsaEncryptTv,rsaDecryptTv;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initLayout();





        AesEncryptAndDecrypt(data);

        RsaEncryptAndDecrypt(data);




    }

    private void initLayout() {
        aesEncryptTv = (TextView)findViewById(R.id.aesEncryptTv);
        aesDecryptTv = (TextView)findViewById(R.id.aesDecryptTv);
        rsaEncryptTv = (TextView)findViewById(R.id.rsaEncryptTv);
        rsaDecryptTv = (TextView)findViewById(R.id.rsaDecryptTv);
    }

    private void setAESValue(String encrypt , String decrypt) {
        aesEncryptTv .setText(encrypt);
        aesDecryptTv.setText(decrypt);

    }

    private void setRSAValue(String encrypt , String decrypt) {

        rsaEncryptTv .setText(encrypt);
        rsaDecryptTv .setText(decrypt);
    }

    /*   Method used to encrypt and decrypt data using AES Algorithm*/
    private void AesEncryptAndDecrypt(String data) {
        String encryptedData =  AES.encrypt(data, key);
        Log.i("AES Encryption Data" , encryptedData+"");

       // decrypt Data
        String decryptedData = AES.decrypt(encryptedData);
        Log.i("AES Decrypted Data" , decryptedData+"");



        setAESValue("AES Encrypted : "+encryptedData,"AES Decrypted : "+decryptedData);

    }
    /*   Method used to encrypt and decrypt data using RSA Algorithm*/

    private void RsaEncryptAndDecrypt(String data) {

        RSA rsa = new RSA();
        try {

            rsa.generateAndSaveRsaKey();   // generate public private modulus and exponentioal

            String rsaEnryptedData = rsa.rsaEncrypt(data);
            Log.i("RSA Encryption Data" , rsaEnryptedData);


            String rsaDeryptedData =  rsa.rsaDecrypt(rsaEnryptedData);
            Log.i("RSA Decrypted Data" , rsaDeryptedData);

            setRSAValue("RSA Encrypted : "+rsaEnryptedData,"RSA Decrypted : "+rsaDeryptedData);

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }
}
