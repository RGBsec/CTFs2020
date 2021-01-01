package com.google.android.gms.common.util;

import android.database.CharArrayBuffer;
import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.text.TextUtils;
import java.io.ByteArrayOutputStream;

public final class DataUtils {
    public static void copyStringToBuffer(String str, CharArrayBuffer charArrayBuffer) {
        if (TextUtils.isEmpty(str)) {
            charArrayBuffer.sizeCopied = 0;
        } else if (charArrayBuffer.data == null || charArrayBuffer.data.length < str.length()) {
            charArrayBuffer.data = str.toCharArray();
        } else {
            str.getChars(0, str.length(), charArrayBuffer.data, 0);
        }
        charArrayBuffer.sizeCopied = str.length();
    }

    public static byte[] loadImageBytes(Bitmap bitmap) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        bitmap.compress(CompressFormat.JPEG, 100, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }
}
