package androidx.core.p005os;

import android.os.Build.VERSION;
import android.os.Message;

/* renamed from: androidx.core.os.MessageCompat */
public final class MessageCompat {
    private static boolean sTryIsAsynchronous = true;
    private static boolean sTrySetAsynchronous = true;

    public static void setAsynchronous(Message message, boolean async) {
        if (VERSION.SDK_INT >= 22) {
            message.setAsynchronous(async);
            return;
        }
        if (sTrySetAsynchronous && VERSION.SDK_INT >= 16) {
            try {
                message.setAsynchronous(async);
            } catch (NoSuchMethodError e) {
                sTrySetAsynchronous = false;
            }
        }
    }

    public static boolean isAsynchronous(Message message) {
        if (VERSION.SDK_INT >= 22) {
            return message.isAsynchronous();
        }
        if (sTryIsAsynchronous && VERSION.SDK_INT >= 16) {
            try {
                return message.isAsynchronous();
            } catch (NoSuchMethodError e) {
                sTryIsAsynchronous = false;
            }
        }
        return false;
    }

    private MessageCompat() {
    }
}
