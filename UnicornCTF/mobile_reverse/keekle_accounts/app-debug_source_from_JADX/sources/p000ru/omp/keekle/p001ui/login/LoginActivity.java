package p000ru.omp.keekle.p001ui.login;

import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.TextView.OnEditorActionListener;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelProvider.Factory;
import androidx.lifecycle.ViewModelProviders;
import ru.omp.task_1.R;

/* renamed from: ru.omp.keekle.ui.login.LoginActivity */
public class LoginActivity extends AppCompatActivity {
    /* access modifiers changed from: private */
    public LoginViewModel loginViewModel;

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) R.layout.activity_login);
        this.loginViewModel = (LoginViewModel) ViewModelProviders.m11of((FragmentActivity) this, (Factory) new LoginViewModelFactory()).get(LoginViewModel.class);
        final EditText usernameEditText = (EditText) findViewById(R.id.username);
        final EditText passwordEditText = (EditText) findViewById(R.id.password);
        final Button loginButton = (Button) findViewById(R.id.login);
        final ProgressBar loadingProgressBar = (ProgressBar) findViewById(R.id.loading);
        this.loginViewModel.getLoginFormState().observe(this, new Observer<LoginFormState>() {
            public void onChanged(LoginFormState loginFormState) {
                if (loginFormState != null) {
                    loginButton.setEnabled(loginFormState.isDataValid());
                    if (loginFormState.getUsernameError() != null) {
                        usernameEditText.setError(LoginActivity.this.getString(loginFormState.getUsernameError().intValue()));
                    }
                    if (loginFormState.getPasswordError() != null) {
                        passwordEditText.setError(LoginActivity.this.getString(loginFormState.getPasswordError().intValue()));
                    }
                }
            }
        });
        this.loginViewModel.getLoginResult().observe(this, new Observer<LoginResult>() {
            public void onChanged(LoginResult loginResult) {
                if (loginResult != null) {
                    loadingProgressBar.setVisibility(8);
                    if (loginResult.getError() != null) {
                        LoginActivity.this.showLoginFailed(loginResult.getError());
                    }
                    if (loginResult.getSuccess() != null) {
                        LoginActivity.this.updateUiWithUser(loginResult.getSuccess());
                    }
                }
            }
        });
        TextWatcher afterTextChangedListener = new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                LoginActivity.this.loginViewModel.loginDataChanged(usernameEditText.getText().toString(), passwordEditText.getText().toString());
            }
        };
        usernameEditText.addTextChangedListener(afterTextChangedListener);
        passwordEditText.addTextChangedListener(afterTextChangedListener);
        passwordEditText.setOnEditorActionListener(new OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                if (actionId == 6) {
                    LoginActivity.this.loginViewModel.login(usernameEditText.getText().toString(), passwordEditText.getText().toString(), LoginActivity.this.getBaseContext());
                }
                return false;
            }
        });
        loginButton.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                loadingProgressBar.setVisibility(0);
                LoginActivity.this.loginViewModel.login(usernameEditText.getText().toString(), passwordEditText.getText().toString(), LoginActivity.this.getBaseContext());
            }
        });
    }

    /* access modifiers changed from: private */
    public void updateUiWithUser(LoggedInUserView model) {
        StringBuilder sb = new StringBuilder();
        sb.append(getString(R.string.welcome));
        sb.append(model.getDisplayName());
        Toast.makeText(getApplicationContext(), sb.toString(), 1).show();
    }

    /* access modifiers changed from: private */
    public void showLoginFailed(Integer errorString) {
        Toast.makeText(getApplicationContext(), errorString.intValue(), 0).show();
    }
}
