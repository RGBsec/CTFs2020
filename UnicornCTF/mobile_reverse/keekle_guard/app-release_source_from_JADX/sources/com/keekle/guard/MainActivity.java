package com.keekle.guard;

import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    public native String decrypt(String str);

    static {
        System.loadLibrary("container");
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView((int) C0270R.layout.activity_main);
        final EditText editText = (EditText) findViewById(C0270R.C0272id.password_field);
        ((Button) findViewById(C0270R.C0272id.confirm_password_button)).setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                String obj = editText.getText().toString();
                editText.setText("");
                TextView textView = (TextView) MainActivity.this.findViewById(C0270R.C0272id.guard_text);
                String decrypt = MainActivity.this.decrypt(obj);
                if (!decrypt.isEmpty()) {
                    textView.setTextSize(7.0f);
                    textView.setText(decrypt);
                    return;
                }
                Toast.makeText(MainActivity.this.getApplicationContext(), C0270R.string.wrong_password, 0).show();
            }
        });
    }
}
