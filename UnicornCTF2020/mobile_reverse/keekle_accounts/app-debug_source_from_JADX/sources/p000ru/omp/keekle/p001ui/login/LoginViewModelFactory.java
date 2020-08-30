package p000ru.omp.keekle.p001ui.login;

import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider.Factory;
import p000ru.omp.keekle.data.LoginDataSource;
import p000ru.omp.keekle.data.LoginRepository;

/* renamed from: ru.omp.keekle.ui.login.LoginViewModelFactory */
public class LoginViewModelFactory implements Factory {
    public <T extends ViewModel> T create(Class<T> modelClass) {
        if (modelClass.isAssignableFrom(LoginViewModel.class)) {
            return new LoginViewModel(LoginRepository.getInstance(new LoginDataSource()));
        }
        throw new IllegalArgumentException("Unknown ViewModel class");
    }
}
