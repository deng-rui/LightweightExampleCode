package kim.der.ironcore.test;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 获取并解密 ijrsoftware CPU-L 数据库数据
 *
 * @author Dr (dr@der.kim)
 * @date 2025/3/22 10:38
 */
public class CpuLDataJson {
    public static void main(String[] args) throws Exception {
        // MD5 hash of the string "com.ijsoft.cpul"
        byte[] bytes = md5("com.ijsoft.cpul").getBytes();

        // HEX TO 16Bytes IV
        byte[] bArr = new byte[16];
        int i7 = 0;
        while (i7 < bytes.length) {
            bArr[i7 / 2] = bytes[31 - i7];
            i7 += 2;
        }

        IvParameterSpec ivParameterSpec = new IvParameterSpec(bArr);
        SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try (CipherOutputStream cipherOut = new CipherOutputStream(out, cipher)) {
            // 这个 URL 来自 : https://www.ijrsoftware.com/json/db_cpus.json
            // 我懒得解 Json 了 (不想引入包, 毕竟只是一个示例)
            // {"release":202503171,"url":"http://www.ijrsoftware.com/db/cpus","version":14,"size":580}
            cipherOut.write(doGetRequestForFile("https://www.ijrsoftware.com/db/cpus"));
        }

        try (FileOutputStream outFile = new FileOutputStream("/de-assets.zip")) {
            outFile.write(out.toByteArray());
        }

        System.out.println("OK, File: "+ new File("/de-assets.zip").getAbsolutePath());
    }

    public static String md5(String md5) {
        //byte[] bytes = context.getPackageName().getBytes();
        byte[] bytes = md5.getBytes();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(bytes);
            byte[] digest = messageDigest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b7 : digest) {
                StringBuilder hexString = new StringBuilder(Integer.toHexString(b7 & 255));
                while (hexString.length() < 2) {
                    hexString.insert(0, "0");
                }
                sb.append(hexString);
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException unused) {
            return "";
        }
    }

    public static byte[] doGetRequestForFile(String urlStr) {
        InputStream is = null;
        ByteArrayOutputStream os = null;
        byte[] buff = new byte[1024];
        int len = 0;
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestProperty("Content-Type", "plain/text;charset=UTF-8");
            conn.setRequestProperty("charset", "UTF-8");
            conn.setDoInput(true);
            conn.setDoOutput(true);
            conn.setRequestMethod("GET");
            conn.setReadTimeout(5000);
            conn.connect();
            is = conn.getInputStream();
            os = new ByteArrayOutputStream();
            while ((len = is.read(buff)) != -1) {
                os.write(buff, 0, len);
            }
            return os.toByteArray();
        } catch (IOException e) {
            return null;
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                }
            }
            if (os != null) {
                try {
                    os.close();
                } catch (IOException e) {
                }
            }
        }
    }
}
