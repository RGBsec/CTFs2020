package p000ru.omp.keekle.data;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/* renamed from: ru.omp.keekle.data.LoginDataController */
public class LoginDataController {
    private static final String HEX = "0123456789ABCDEF";
    private static final byte[] keyValue = "ponyponyponypony".getBytes();

    public static String read(String encrypted) throws Exception {
        return new String(read(toByte(encrypted)));
    }

    private static byte[] getRawKey() throws Exception {
        return new SecretKeySpec(keyValue, "AES").getEncoded();
    }

    private static byte[] read(byte[] encrypted) throws Exception {
        String str = "AES";
        SecretKey skeySpec = new SecretKeySpec(keyValue, str);
        Cipher cipher = Cipher.getInstance(str);
        cipher.init(2, skeySpec);
        return cipher.doFinal(encrypted);
    }

    public static byte[] toByte(String hexString) {
        int len = hexString.length() / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = Integer.valueOf(hexString.substring(i * 2, (i * 2) + 2), 16).byteValue();
        }
        return result;
    }

    public static String toHex(byte[] buf) {
        if (buf == null) {
            return "";
        }
        StringBuffer result = new StringBuffer(buf.length * 2);
        for (byte appendHex : buf) {
            appendHex(result, appendHex);
        }
        return result.toString();
    }

    private static void appendHex(StringBuffer sb, byte b) {
        int i = (b >> 4) & 15;
        String str = HEX;
        sb.append(str.charAt(i));
        sb.append(str.charAt(b & 15));
    }
}
