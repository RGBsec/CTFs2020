package p000ru.omp.keekle.data;

/* renamed from: ru.omp.keekle.data.Result */
public class Result<T> {

    /* renamed from: ru.omp.keekle.data.Result$Develop */
    public static final class Develop<T> extends Result {
        private T data;

        public Develop(T data2) {
            super();
            this.data = data2;
        }

        public T getData() {
            return this.data;
        }
    }

    /* renamed from: ru.omp.keekle.data.Result$Error */
    public static final class Error extends Result {
        private Exception error;

        public Error(Exception error2) {
            super();
            this.error = error2;
        }

        public Exception getError() {
            return this.error;
        }
    }

    /* renamed from: ru.omp.keekle.data.Result$Success */
    public static final class Success<T> extends Result {
        private T data;

        public Success(T data2) {
            super();
            this.data = data2;
        }

        public T getData() {
            return this.data;
        }
    }

    private Result() {
    }

    public String toString() {
        String str = "]";
        if (this instanceof Success) {
            Success success = (Success) this;
            StringBuilder sb = new StringBuilder();
            sb.append("Success[data=");
            sb.append(success.getData().toString());
            sb.append(str);
            return sb.toString();
        } else if (!(this instanceof Error)) {
            return "";
        } else {
            Error error = (Error) this;
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Error[exception=");
            sb2.append(error.getError().toString());
            sb2.append(str);
            return sb2.toString();
        }
    }
}
