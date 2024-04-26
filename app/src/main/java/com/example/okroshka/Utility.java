package com.example.okroshka;

import android.content.Context;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: classes.dex */
public class Utility {
  private static final String AES_GCM = "AES/GCM/NoPadding";
  private static final String HMAC_SHA256 = "HmacSHA256";
  private static final String MD5 = "MD5";
  private static final String TAG = "Utility";
  private static final byte[] encryptionKey = {
      100, 97, 116, 97, 98, 97, 115, 101, 101, 110, 99, 114, 121, 112, 116, 105, 111, 110, 107, 101, 121
  };

  private static byte[] readFile(File file) throws Exception {
    FileInputStream fileInputStream = new FileInputStream(file);
    byte[] bArr = new byte[(int) file.length()];
    fileInputStream.read(bArr);
    fileInputStream.close();
    return bArr;
  }

  private static void createStaticFile(Context context, String str) throws Exception {
    byte[] bytes = str.getBytes();
    byte[] bArr = new byte[16];
    for (int i = 0; i < 16; i++) {
      bArr[i] = 0;
    }
    SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
    Mac mac = Mac.getInstance(HMAC_SHA256);
    mac.init(secretKeySpec);
    byte[] doFinal = mac.doFinal(bytes);
    byte[] bArr2 = new byte[16];
    SecretKeySpec secretKeySpec2 = new SecretKeySpec(doFinal, "AES");
    Mac mac2 = Mac.getInstance(HMAC_SHA256);
    mac2.init(secretKeySpec2);
    System.arraycopy(mac2.doFinal(bytes), 0, bArr2, 0, 16);
    FileOutputStream fileOutputStream = new FileOutputStream(new File(context.getFilesDir(), "enc_key"));
    ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
    objectOutputStream.writeObject(bArr2);
    objectOutputStream.close();
    fileOutputStream.close();
  }

  private static byte[] readStaticFile(Context context) throws Exception {
    File file = new File(context.getFilesDir(), "enc_key");
    if (!file.exists()) {
      throw new FileNotFoundException("Encryption key file not found");
    }
    FileInputStream fileInputStream = new FileInputStream(file);
    ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
    byte[] bArr = (byte[]) objectInputStream.readObject();
    objectInputStream.close();
    fileInputStream.close();
    if (bArr.length == 16) {
      return bArr;
    }
    throw new Exception("Invalid encryption key length");
  }

  public static void encryptDatabase(File file, File file2, String str, Context context) throws Exception {
    byte[] readStaticFile;
    String substring = str.substring(str.length() - 3);
    try {
      try {
        readStaticFile = readStaticFile(context);
      } catch (Exception e) {
        e.printStackTrace();
        return;
      }
    } catch (Exception unused) {
      createStaticFile(context, substring);
      readStaticFile = readStaticFile(context);
    }
    SecretKeySpec secretKeySpec = new SecretKeySpec(readStaticFile, "AES");
    try {
      Mac mac = Mac.getInstance(HMAC_SHA256);
      try {
        mac.init(secretKeySpec);
        byte[] bArr = new byte[16];
        System.arraycopy(mac.doFinal(encryptionKey), 0, bArr, 0, 16);
        SecretKeySpec secretKeySpec2 = new SecretKeySpec(bArr, "AES");
        try {
          Cipher cipher = Cipher.getInstance(AES_GCM);
          byte[] bArr2 = new byte[16];
          new SecureRandom().nextBytes(bArr2);
          try {
            cipher.init(1, secretKeySpec2, new IvParameterSpec(bArr2));
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream);
            byte[] readFile = readFile(file);
            deflaterOutputStream.write(readFile);
            deflaterOutputStream.close();
            byte[] doFinal = cipher.doFinal(byteArrayOutputStream.toByteArray());
            byte[] digest = MessageDigest.getInstance(MD5).digest(readFile);
            String str2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()) + "_" + substring;
            ByteBuffer allocate = ByteBuffer.allocate(str2.getBytes().length + 18);
            allocate.putShort((short) (str2.getBytes().length + 16));
            allocate.put(bArr2);
            allocate.put(str2.getBytes());
            FileOutputStream fileOutputStream = new FileOutputStream(file2);
            fileOutputStream.write(allocate.array());
            fileOutputStream.write(doFinal);
            fileOutputStream.write(digest);
            fileOutputStream.close();
          } catch (Exception e2) {
            e2.printStackTrace();
          }
        } catch (Exception e3) {
          e3.printStackTrace();
        }
      } catch (Exception e4) {
        e4.printStackTrace();
      }
    } catch (Exception e5) {
      e5.printStackTrace();
    }
  }

  public static void decryptDatabase(File encrypted, File decrypted, String substring, Context context) throws Exception {
    byte[] readStaticFile;
    try {
      readStaticFile = readStaticFile(context);
    } catch (Exception unused) {
      createStaticFile(context, substring);
      readStaticFile = readStaticFile(context);
    }
    SecretKeySpec secretKeySpec = new SecretKeySpec(readStaticFile, "AES");
    try {
      Mac mac = Mac.getInstance(HMAC_SHA256);
      try {
        mac.init(secretKeySpec);
        byte[] bArr = new byte[16];
        System.arraycopy(mac.doFinal(encryptionKey), 0, bArr, 0, 16);
        SecretKeySpec secretKeySpec2 = new SecretKeySpec(bArr, "AES");
        try {
          Cipher cipher = Cipher.getInstance(AES_GCM);
          try {
            byte[] readFile = readFile(encrypted);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(readFile);

            byte[] shortBytes = new byte[2];
            byteArrayInputStream.read(shortBytes);
            System.out.println("short: " + new String(shortBytes));

            byte[] ivBytes = new byte[16];
            byteArrayInputStream.read(ivBytes);
            System.out.println("iv: " + new String(ivBytes));

            String str2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()) + "_" + substring;
            byte[] metadataBytes = new byte[str2.getBytes().length];
            byteArrayInputStream.read(metadataBytes);
            System.out.println("metadata: " + new String(metadataBytes));


            byte[] encryptedDbBytes = new byte[readFile.length - str2.getBytes().length - 18 - 16];
            byteArrayInputStream.read(encryptedDbBytes);

            cipher.init(2, secretKeySpec2, new IvParameterSpec(ivBytes));
            byte[] decryptedDbBytes = cipher.doFinal(encryptedDbBytes);


            FileOutputStream fileOutputStream = new FileOutputStream(decrypted);
            final ByteArrayInputStream bais = new ByteArrayInputStream(decryptedDbBytes);
            final InflaterInputStream gz = new InflaterInputStream(bais);
            int read;
            while ((read = gz.read()) != -1) {
              fileOutputStream.write(read);
            }
            gz.close();
            bais.close();
            fileOutputStream.close();
          } catch (Exception e2) {
            e2.printStackTrace();
          }
        } catch (Exception e3) {
          e3.printStackTrace();
        }
      } catch (Exception e4) {
        e4.printStackTrace();
      }
    } catch (Exception e5) {
      e5.printStackTrace();
    }
  }
}