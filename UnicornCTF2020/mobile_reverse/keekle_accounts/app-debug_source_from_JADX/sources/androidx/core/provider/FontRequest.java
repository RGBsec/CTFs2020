package androidx.core.provider;

import android.util.Base64;
import androidx.core.util.Preconditions;
import java.util.List;

public final class FontRequest {
    private final List<List<byte[]>> mCertificates;
    private final int mCertificatesArray;
    private final String mIdentifier;
    private final String mProviderAuthority;
    private final String mProviderPackage;
    private final String mQuery;

    public FontRequest(String providerAuthority, String providerPackage, String query, List<List<byte[]>> certificates) {
        this.mProviderAuthority = (String) Preconditions.checkNotNull(providerAuthority);
        this.mProviderPackage = (String) Preconditions.checkNotNull(providerPackage);
        this.mQuery = (String) Preconditions.checkNotNull(query);
        this.mCertificates = (List) Preconditions.checkNotNull(certificates);
        this.mCertificatesArray = 0;
        StringBuilder sb = new StringBuilder(this.mProviderAuthority);
        String str = "-";
        sb.append(str);
        sb.append(this.mProviderPackage);
        sb.append(str);
        sb.append(this.mQuery);
        this.mIdentifier = sb.toString();
    }

    public FontRequest(String providerAuthority, String providerPackage, String query, int certificates) {
        this.mProviderAuthority = (String) Preconditions.checkNotNull(providerAuthority);
        this.mProviderPackage = (String) Preconditions.checkNotNull(providerPackage);
        this.mQuery = (String) Preconditions.checkNotNull(query);
        this.mCertificates = null;
        Preconditions.checkArgument(certificates != 0);
        this.mCertificatesArray = certificates;
        StringBuilder sb = new StringBuilder(this.mProviderAuthority);
        String str = "-";
        sb.append(str);
        sb.append(this.mProviderPackage);
        sb.append(str);
        sb.append(this.mQuery);
        this.mIdentifier = sb.toString();
    }

    public String getProviderAuthority() {
        return this.mProviderAuthority;
    }

    public String getProviderPackage() {
        return this.mProviderPackage;
    }

    public String getQuery() {
        return this.mQuery;
    }

    public List<List<byte[]>> getCertificates() {
        return this.mCertificates;
    }

    public int getCertificatesArrayResId() {
        return this.mCertificatesArray;
    }

    public String getIdentifier() {
        return this.mIdentifier;
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        StringBuilder sb = new StringBuilder();
        sb.append("FontRequest {mProviderAuthority: ");
        sb.append(this.mProviderAuthority);
        sb.append(", mProviderPackage: ");
        sb.append(this.mProviderPackage);
        sb.append(", mQuery: ");
        sb.append(this.mQuery);
        sb.append(", mCertificates:");
        builder.append(sb.toString());
        for (int i = 0; i < this.mCertificates.size(); i++) {
            builder.append(" [");
            List<byte[]> set = (List) this.mCertificates.get(i);
            for (int j = 0; j < set.size(); j++) {
                builder.append(" \"");
                builder.append(Base64.encodeToString((byte[]) set.get(j), 0));
                builder.append("\"");
            }
            builder.append(" ]");
        }
        builder.append("}");
        StringBuilder sb2 = new StringBuilder();
        sb2.append("mCertificatesArray: ");
        sb2.append(this.mCertificatesArray);
        builder.append(sb2.toString());
        return builder.toString();
    }
}
