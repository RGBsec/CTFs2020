package com.google.android.gms.common.util;

public final class HexDumpUtils {
    public static String dump(byte[] bArr, int i, int i2, boolean z) {
        if (bArr == null || bArr.length == 0 || i < 0 || i2 <= 0 || i + i2 > bArr.length) {
            return null;
        }
        int i3 = 57;
        if (z) {
            i3 = 75;
        }
        StringBuilder sb = new StringBuilder(i3 * (((i2 + 16) - 1) / 16));
        int i4 = i2;
        int i5 = 0;
        int i6 = 0;
        while (i4 > 0) {
            if (i5 == 0) {
                if (i2 < 65536) {
                    sb.append(String.format("%04X:", new Object[]{Integer.valueOf(i)}));
                } else {
                    sb.append(String.format("%08X:", new Object[]{Integer.valueOf(i)}));
                }
                i6 = i;
            } else if (i5 == 8) {
                sb.append(" -");
            }
            sb.append(String.format(" %02X", new Object[]{Integer.valueOf(bArr[i] & 255)}));
            i4--;
            i5++;
            if (z && (i5 == 16 || i4 == 0)) {
                int i7 = 16 - i5;
                if (i7 > 0) {
                    for (int i8 = 0; i8 < i7; i8++) {
                        sb.append("   ");
                    }
                }
                String str = "  ";
                if (i7 >= 8) {
                    sb.append(str);
                }
                sb.append(str);
                for (int i9 = 0; i9 < i5; i9++) {
                    char c = (char) bArr[i6 + i9];
                    if (c < ' ' || c > '~') {
                        c = '.';
                    }
                    sb.append(c);
                }
            }
            if (i5 == 16 || i4 == 0) {
                sb.append(10);
                i5 = 0;
            }
            i++;
        }
        return sb.toString();
    }
}
