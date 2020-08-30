package p000ru.omp.keekle.p001ui.login;

/* renamed from: ru.omp.keekle.ui.login.LoginResult */
class LoginResult {
    private Integer error;
    private LoggedInUserView success;

    LoginResult(Integer error2) {
        this.error = error2;
    }

    LoginResult(LoggedInUserView success2) {
        this.success = success2;
    }

    /* access modifiers changed from: 0000 */
    public LoggedInUserView getSuccess() {
        return this.success;
    }

    /* access modifiers changed from: 0000 */
    public Integer getError() {
        return this.error;
    }
}
