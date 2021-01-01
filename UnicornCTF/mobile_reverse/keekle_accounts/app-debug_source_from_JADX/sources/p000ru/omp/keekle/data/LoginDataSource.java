package p000ru.omp.keekle.data;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import p000ru.omp.keekle.data.Result.Develop;
import p000ru.omp.keekle.data.Result.Error;
import p000ru.omp.keekle.data.Result.Success;
import p000ru.omp.keekle.data.model.LoggedInUser;
import ru.omp.task_1.R;

/* renamed from: ru.omp.keekle.data.LoginDataSource */
public class LoginDataSource {
    private static String md5(String st) {
        byte[] digest = new byte[0];
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.reset();
            messageDigest.update(st.getBytes());
            digest = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        StringBuilder md5Hex = new StringBuilder(new BigInteger(1, digest).toString(16));
        while (md5Hex.length() < 32) {
            md5Hex.insert(0, "0");
        }
        return md5Hex.toString();
    }

    private boolean cmpdvpwd(String uuid, String pwd) {
        return uuid.equals(pwd);
    }

    public Result<LoggedInUser> login(String username, String password, Context context) throws Exception {
        String str = "Wrong password for ";
        StringBuilder sb = new StringBuilder();
        sb.append(context.getFilesDir());
        sb.append("dev.keekledev");
        File d = new File(sb.toString());
        String str2 = "Error logging in";
        if (!d.exists()) {
            d.createNewFile();
            if (!d.canWrite()) {
                return new Error(new IOException(str2, new Exception("You're about developer")));
            }
            new FileOutputStream(d).write(UUID.randomUUID().toString().getBytes());
            return new Error(new IOException(str2, new Exception()));
        } else if (!d.canRead() || !username.equals("developer")) {
            SQLiteDatabase db = context.openOrCreateDatabase("userdata.db", 0, null);
            try {
                if (db.isOpen()) {
                    db.execSQL("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)");
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("SELECT * FROM users WHERE username='");
                    sb2.append(username);
                    sb2.append("'");
                    Cursor query = db.rawQuery(sb2.toString(), null);
                    if (query.getCount() == 0) {
                        StringBuilder sb3 = new StringBuilder();
                        sb3.append("User ");
                        sb3.append(username);
                        sb3.append(" was registered");
                        Toast.makeText(context, sb3.toString(), 0).show();
                        String hashed = md5(password);
                        ContentValues values = new ContentValues();
                        values.put("username", username);
                        values.put("password", hashed);
                        db.insert("users", null, values);
                        db.close();
                        return new Success(new LoggedInUser(UUID.randomUUID().toString(), username));
                    }
                    query.moveToFirst();
                    if (md5(password).equals(md5(query.getString(1)))) {
                        return new Success(new LoggedInUser(UUID.randomUUID().toString(), username));
                    }
                    StringBuilder sb4 = new StringBuilder();
                    sb4.append(str);
                    sb4.append(username);
                    Toast.makeText(context, sb4.toString(), 0).show();
                    StringBuilder sb5 = new StringBuilder();
                    sb5.append(str);
                    sb5.append(username);
                    throw new Exception(sb5.toString());
                }
                throw new Exception("Unable to open database");
            } catch (Exception e) {
                return new Error(new IOException(str2, e));
            }
        } else {
            BufferedReader br = new BufferedReader(new FileReader(d));
            StringBuilder uuid = new StringBuilder();
            while (true) {
                String readLine = br.readLine();
                String line = readLine;
                if (readLine != null) {
                    uuid.append(line);
                } else {
                    br.close();
                    InputStream developerName = context.getResources().openRawResource(R.raw.devkey);
                    byte[] enc = new byte[developerName.available()];
                    developerName.read(enc);
                    return new Develop(new LoggedInUser(uuid.toString(), LoginDataController.read(new String(enc))));
                }
            }
        }
    }
}
