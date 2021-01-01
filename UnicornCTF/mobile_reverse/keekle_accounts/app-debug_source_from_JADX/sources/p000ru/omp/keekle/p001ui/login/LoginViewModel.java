package p000ru.omp.keekle.p001ui.login;

import android.content.Context;
import android.util.Patterns;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;
import p000ru.omp.keekle.data.LoginRepository;
import p000ru.omp.keekle.data.Result;
import p000ru.omp.keekle.data.Result.Develop;
import p000ru.omp.keekle.data.Result.Success;
import p000ru.omp.keekle.data.model.LoggedInUser;
import ru.omp.task_1.R;

/* renamed from: ru.omp.keekle.ui.login.LoginViewModel */
public class LoginViewModel extends ViewModel {
    private MutableLiveData<LoginFormState> loginFormState = new MutableLiveData<>();
    private LoginRepository loginRepository;
    private MutableLiveData<LoginResult> loginResult = new MutableLiveData<>();

    LoginViewModel(LoginRepository loginRepository2) {
        this.loginRepository = loginRepository2;
    }

    /* access modifiers changed from: 0000 */
    public LiveData<LoginFormState> getLoginFormState() {
        return this.loginFormState;
    }

    /* access modifiers changed from: 0000 */
    public LiveData<LoginResult> getLoginResult() {
        return this.loginResult;
    }

    public void login(String username, String password, Context context) {
        Result<LoggedInUser> result = this.loginRepository.login(username, password, context);
        if (result instanceof Success) {
            this.loginResult.setValue(new LoginResult(new LoggedInUserView(((LoggedInUser) ((Success) result).getData()).getDisplayName())));
        } else if (result instanceof Develop) {
            this.loginResult.setValue(new LoginResult(new LoggedInUserView(((LoggedInUser) ((Develop) result).getData()).getDisplayName())));
        } else {
            this.loginResult.setValue(new LoginResult(Integer.valueOf(R.string.login_failed)));
        }
    }

    public void loginDataChanged(String username, String password) {
        if (!isUserNameValid(username)) {
            this.loginFormState.setValue(new LoginFormState(Integer.valueOf(R.string.invalid_username), null));
        } else if (!isPasswordValid(password)) {
            this.loginFormState.setValue(new LoginFormState(null, Integer.valueOf(R.string.invalid_password)));
        } else {
            this.loginFormState.setValue(new LoginFormState(true));
        }
    }

    private boolean isUserNameValid(String username) {
        if (username == null) {
            return false;
        }
        if (username.contains("@")) {
            return Patterns.EMAIL_ADDRESS.matcher(username).matches();
        }
        if (!username.matches("^[a-zA-Z1-9@]*$")) {
            return false;
        }
        return !username.trim().isEmpty();
    }

    private boolean isPasswordValid(String password) {
        return password != null && password.trim().length() > 5;
    }
}
