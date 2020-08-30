package p000ru.omp.keekle.data;

import android.content.Context;
import java.io.IOException;
import p000ru.omp.keekle.data.Result.Error;
import p000ru.omp.keekle.data.model.LoggedInUser;

/* renamed from: ru.omp.keekle.data.LoginRepository */
public class LoginRepository {
    private static volatile LoginRepository instance;
    private LoginDataSource dataSource;

    private LoginRepository(LoginDataSource dataSource2) {
        this.dataSource = dataSource2;
    }

    public static LoginRepository getInstance(LoginDataSource dataSource2) {
        if (instance == null) {
            instance = new LoginRepository(dataSource2);
        }
        return instance;
    }

    public Result<LoggedInUser> login(String username, String password, Context context) {
        try {
            return this.dataSource.login(username, password, context);
        } catch (Exception e) {
            e.printStackTrace();
            return new Error(new IOException("Error logging in", e));
        }
    }
}
