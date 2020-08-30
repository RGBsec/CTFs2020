package p000ru.omp.keekle.p001ui.login;

/* renamed from: ru.omp.keekle.ui.login.LoginFormState */
class LoginFormState {
    private boolean isDataValid;
    private Integer passwordError;
    private Integer usernameError;

    LoginFormState(Integer usernameError2, Integer passwordError2) {
        this.usernameError = usernameError2;
        this.passwordError = passwordError2;
        this.isDataValid = false;
    }

    LoginFormState(boolean isDataValid2) {
        this.usernameError = null;
        this.passwordError = null;
        this.isDataValid = isDataValid2;
    }

    /* access modifiers changed from: 0000 */
    public Integer getUsernameError() {
        return this.usernameError;
    }

    /* access modifiers changed from: 0000 */
    public Integer getPasswordError() {
        return this.passwordError;
    }

    /* access modifiers changed from: 0000 */
    public boolean isDataValid() {
        return this.isDataValid;
    }
}
