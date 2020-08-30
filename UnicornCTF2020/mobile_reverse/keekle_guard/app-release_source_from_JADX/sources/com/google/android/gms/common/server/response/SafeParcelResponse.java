package com.google.android.gms.common.server.response;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable.Creator;
import android.util.SparseArray;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.common.internal.safeparcel.SafeParcelReader;
import com.google.android.gms.common.internal.safeparcel.SafeParcelReader.ParseException;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.server.response.FastJsonResponse.Field;
import com.google.android.gms.common.util.ArrayUtils;
import com.google.android.gms.common.util.Base64Utils;
import com.google.android.gms.common.util.JsonUtils;
import com.google.android.gms.common.util.MapUtils;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

public class SafeParcelResponse extends FastSafeParcelableJsonResponse {
    public static final Creator<SafeParcelResponse> CREATOR = new zap();
    private final String mClassName;
    private final int zalf;
    private final zak zapz;
    private final Parcel zarb;
    private final int zarc;
    private int zard;
    private int zare;

    public SafeParcelResponse(zak zak, String str) {
        this.zalf = 1;
        this.zarb = Parcel.obtain();
        this.zarc = 0;
        this.zapz = (zak) Preconditions.checkNotNull(zak);
        this.mClassName = (String) Preconditions.checkNotNull(str);
        this.zard = 0;
    }

    private SafeParcelResponse(SafeParcelable safeParcelable, zak zak, String str) {
        this.zalf = 1;
        Parcel obtain = Parcel.obtain();
        this.zarb = obtain;
        safeParcelable.writeToParcel(obtain, 0);
        this.zarc = 1;
        this.zapz = (zak) Preconditions.checkNotNull(zak);
        this.mClassName = (String) Preconditions.checkNotNull(str);
        this.zard = 2;
    }

    public static <T extends FastJsonResponse & SafeParcelable> SafeParcelResponse from(T t) {
        String canonicalName = t.getClass().getCanonicalName();
        zak zak = new zak(t.getClass());
        zaa(zak, t);
        zak.zacs();
        zak.zacr();
        return new SafeParcelResponse((SafeParcelable) t, zak, canonicalName);
    }

    private static void zaa(zak zak, FastJsonResponse fastJsonResponse) {
        Class cls = fastJsonResponse.getClass();
        if (!zak.zaa(cls)) {
            Map fieldMappings = fastJsonResponse.getFieldMappings();
            zak.zaa(cls, fieldMappings);
            for (String str : fieldMappings.keySet()) {
                Field field = (Field) fieldMappings.get(str);
                Class<? extends FastJsonResponse> cls2 = field.zapx;
                if (cls2 != null) {
                    try {
                        zaa(zak, (FastJsonResponse) cls2.newInstance());
                    } catch (InstantiationException e) {
                        String str2 = "Could not instantiate an object of type ";
                        String valueOf = String.valueOf(field.zapx.getCanonicalName());
                        throw new IllegalStateException(valueOf.length() != 0 ? str2.concat(valueOf) : new String(str2), e);
                    } catch (IllegalAccessException e2) {
                        String str3 = "Could not access object of type ";
                        String valueOf2 = String.valueOf(field.zapx.getCanonicalName());
                        throw new IllegalStateException(valueOf2.length() != 0 ? str3.concat(valueOf2) : new String(str3), e2);
                    }
                }
            }
        }
    }

    SafeParcelResponse(int i, Parcel parcel, zak zak) {
        this.zalf = i;
        this.zarb = (Parcel) Preconditions.checkNotNull(parcel);
        this.zarc = 2;
        this.zapz = zak;
        if (zak == null) {
            this.mClassName = null;
        } else {
            this.mClassName = zak.zact();
        }
        this.zard = 2;
    }

    public void writeToParcel(Parcel parcel, int i) {
        zak zak;
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeInt(parcel, 1, this.zalf);
        SafeParcelWriter.writeParcel(parcel, 2, zacu(), false);
        int i2 = this.zarc;
        if (i2 == 0) {
            zak = null;
        } else if (i2 == 1) {
            zak = this.zapz;
        } else if (i2 == 2) {
            zak = this.zapz;
        } else {
            int i3 = this.zarc;
            StringBuilder sb = new StringBuilder(34);
            sb.append("Invalid creation type: ");
            sb.append(i3);
            throw new IllegalStateException(sb.toString());
        }
        SafeParcelWriter.writeParcelable(parcel, 3, zak, i, false);
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:3:0x0005, code lost:
        if (r0 != 1) goto L_0x001a;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private final android.os.Parcel zacu() {
        /*
            r2 = this;
            int r0 = r2.zard
            if (r0 == 0) goto L_0x0008
            r1 = 1
            if (r0 == r1) goto L_0x0010
            goto L_0x001a
        L_0x0008:
            android.os.Parcel r0 = r2.zarb
            int r0 = com.google.android.gms.common.internal.safeparcel.SafeParcelWriter.beginObjectHeader(r0)
            r2.zare = r0
        L_0x0010:
            android.os.Parcel r0 = r2.zarb
            int r1 = r2.zare
            com.google.android.gms.common.internal.safeparcel.SafeParcelWriter.finishObjectHeader(r0, r1)
            r0 = 2
            r2.zard = r0
        L_0x001a:
            android.os.Parcel r0 = r2.zarb
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.server.response.SafeParcelResponse.zacu():android.os.Parcel");
    }

    public Map<String, Field<?, ?>> getFieldMappings() {
        zak zak = this.zapz;
        if (zak == null) {
            return null;
        }
        return zak.zai(this.mClassName);
    }

    public Object getValueObject(String str) {
        throw new UnsupportedOperationException("Converting to JSON does not require this method.");
    }

    public boolean isPrimitiveFieldSet(String str) {
        throw new UnsupportedOperationException("Converting to JSON does not require this method.");
    }

    private final void zab(Field<?, ?> field) {
        if (field.zapw != -1) {
            Parcel parcel = this.zarb;
            if (parcel != null) {
                int i = this.zard;
                if (i == 0) {
                    this.zare = SafeParcelWriter.beginObjectHeader(parcel);
                    this.zard = 1;
                } else if (i == 1) {
                } else {
                    if (i != 2) {
                        throw new IllegalStateException("Unknown parse state in SafeParcelResponse.");
                    }
                    throw new IllegalStateException("Attempted to parse JSON with a SafeParcelResponse object that is already filled with data.");
                }
            } else {
                throw new IllegalStateException("Internal Parcel object is null.");
            }
        } else {
            throw new IllegalStateException("Field does not have a valid safe parcelable field id.");
        }
    }

    /* access modifiers changed from: protected */
    public void setIntegerInternal(Field<?, ?> field, String str, int i) {
        zab(field);
        SafeParcelWriter.writeInt(this.zarb, field.getSafeParcelableFieldId(), i);
    }

    /* access modifiers changed from: protected */
    public final void zaa(Field<?, ?> field, String str, ArrayList<Integer> arrayList) {
        zab(field);
        int size = arrayList.size();
        int[] iArr = new int[size];
        for (int i = 0; i < size; i++) {
            iArr[i] = ((Integer) arrayList.get(i)).intValue();
        }
        SafeParcelWriter.writeIntArray(this.zarb, field.getSafeParcelableFieldId(), iArr, true);
    }

    /* access modifiers changed from: protected */
    public final void zaa(Field<?, ?> field, String str, BigInteger bigInteger) {
        zab(field);
        SafeParcelWriter.writeBigInteger(this.zarb, field.getSafeParcelableFieldId(), bigInteger, true);
    }

    /* access modifiers changed from: protected */
    public final void zab(Field<?, ?> field, String str, ArrayList<BigInteger> arrayList) {
        zab(field);
        int size = arrayList.size();
        BigInteger[] bigIntegerArr = new BigInteger[size];
        for (int i = 0; i < size; i++) {
            bigIntegerArr[i] = (BigInteger) arrayList.get(i);
        }
        SafeParcelWriter.writeBigIntegerArray(this.zarb, field.getSafeParcelableFieldId(), bigIntegerArr, true);
    }

    /* access modifiers changed from: protected */
    public void setLongInternal(Field<?, ?> field, String str, long j) {
        zab(field);
        SafeParcelWriter.writeLong(this.zarb, field.getSafeParcelableFieldId(), j);
    }

    /* access modifiers changed from: protected */
    public final void zac(Field<?, ?> field, String str, ArrayList<Long> arrayList) {
        zab(field);
        int size = arrayList.size();
        long[] jArr = new long[size];
        for (int i = 0; i < size; i++) {
            jArr[i] = ((Long) arrayList.get(i)).longValue();
        }
        SafeParcelWriter.writeLongArray(this.zarb, field.getSafeParcelableFieldId(), jArr, true);
    }

    /* access modifiers changed from: protected */
    public final void zaa(Field<?, ?> field, String str, float f) {
        zab(field);
        SafeParcelWriter.writeFloat(this.zarb, field.getSafeParcelableFieldId(), f);
    }

    /* access modifiers changed from: protected */
    public final void zad(Field<?, ?> field, String str, ArrayList<Float> arrayList) {
        zab(field);
        int size = arrayList.size();
        float[] fArr = new float[size];
        for (int i = 0; i < size; i++) {
            fArr[i] = ((Float) arrayList.get(i)).floatValue();
        }
        SafeParcelWriter.writeFloatArray(this.zarb, field.getSafeParcelableFieldId(), fArr, true);
    }

    /* access modifiers changed from: protected */
    public final void zaa(Field<?, ?> field, String str, double d) {
        zab(field);
        SafeParcelWriter.writeDouble(this.zarb, field.getSafeParcelableFieldId(), d);
    }

    /* access modifiers changed from: protected */
    public final void zae(Field<?, ?> field, String str, ArrayList<Double> arrayList) {
        zab(field);
        int size = arrayList.size();
        double[] dArr = new double[size];
        for (int i = 0; i < size; i++) {
            dArr[i] = ((Double) arrayList.get(i)).doubleValue();
        }
        SafeParcelWriter.writeDoubleArray(this.zarb, field.getSafeParcelableFieldId(), dArr, true);
    }

    /* access modifiers changed from: protected */
    public final void zaa(Field<?, ?> field, String str, BigDecimal bigDecimal) {
        zab(field);
        SafeParcelWriter.writeBigDecimal(this.zarb, field.getSafeParcelableFieldId(), bigDecimal, true);
    }

    /* access modifiers changed from: protected */
    public final void zaf(Field<?, ?> field, String str, ArrayList<BigDecimal> arrayList) {
        zab(field);
        int size = arrayList.size();
        BigDecimal[] bigDecimalArr = new BigDecimal[size];
        for (int i = 0; i < size; i++) {
            bigDecimalArr[i] = (BigDecimal) arrayList.get(i);
        }
        SafeParcelWriter.writeBigDecimalArray(this.zarb, field.getSafeParcelableFieldId(), bigDecimalArr, true);
    }

    /* access modifiers changed from: protected */
    public void setBooleanInternal(Field<?, ?> field, String str, boolean z) {
        zab(field);
        SafeParcelWriter.writeBoolean(this.zarb, field.getSafeParcelableFieldId(), z);
    }

    /* access modifiers changed from: protected */
    public final void zag(Field<?, ?> field, String str, ArrayList<Boolean> arrayList) {
        zab(field);
        int size = arrayList.size();
        boolean[] zArr = new boolean[size];
        for (int i = 0; i < size; i++) {
            zArr[i] = ((Boolean) arrayList.get(i)).booleanValue();
        }
        SafeParcelWriter.writeBooleanArray(this.zarb, field.getSafeParcelableFieldId(), zArr, true);
    }

    /* access modifiers changed from: protected */
    public void setStringInternal(Field<?, ?> field, String str, String str2) {
        zab(field);
        SafeParcelWriter.writeString(this.zarb, field.getSafeParcelableFieldId(), str2, true);
    }

    /* access modifiers changed from: protected */
    public void setStringsInternal(Field<?, ?> field, String str, ArrayList<String> arrayList) {
        zab(field);
        int size = arrayList.size();
        String[] strArr = new String[size];
        for (int i = 0; i < size; i++) {
            strArr[i] = (String) arrayList.get(i);
        }
        SafeParcelWriter.writeStringArray(this.zarb, field.getSafeParcelableFieldId(), strArr, true);
    }

    /* access modifiers changed from: protected */
    public void setDecodedBytesInternal(Field<?, ?> field, String str, byte[] bArr) {
        zab(field);
        SafeParcelWriter.writeByteArray(this.zarb, field.getSafeParcelableFieldId(), bArr, true);
    }

    /* access modifiers changed from: protected */
    public final void zaa(Field<?, ?> field, String str, Map<String, String> map) {
        zab(field);
        Bundle bundle = new Bundle();
        for (String str2 : map.keySet()) {
            bundle.putString(str2, (String) map.get(str2));
        }
        SafeParcelWriter.writeBundle(this.zarb, field.getSafeParcelableFieldId(), bundle, true);
    }

    public <T extends FastJsonResponse> void addConcreteTypeInternal(Field<?, ?> field, String str, T t) {
        zab(field);
        SafeParcelWriter.writeParcel(this.zarb, field.getSafeParcelableFieldId(), ((SafeParcelResponse) t).zacu(), true);
    }

    public <T extends FastJsonResponse> void addConcreteTypeArrayInternal(Field<?, ?> field, String str, ArrayList<T> arrayList) {
        zab(field);
        ArrayList arrayList2 = new ArrayList();
        arrayList.size();
        ArrayList arrayList3 = arrayList;
        int size = arrayList3.size();
        int i = 0;
        while (i < size) {
            Object obj = arrayList3.get(i);
            i++;
            arrayList2.add(((SafeParcelResponse) ((FastJsonResponse) obj)).zacu());
        }
        SafeParcelWriter.writeParcelList(this.zarb, field.getSafeParcelableFieldId(), arrayList2, true);
    }

    public String toString() {
        Preconditions.checkNotNull(this.zapz, "Cannot convert to JSON on client side.");
        Parcel zacu = zacu();
        zacu.setDataPosition(0);
        StringBuilder sb = new StringBuilder(100);
        zaa(sb, this.zapz.zai(this.mClassName), zacu);
        return sb.toString();
    }

    private final void zaa(StringBuilder sb, Map<String, Field<?, ?>> map, Parcel parcel) {
        SparseArray sparseArray = new SparseArray();
        for (Entry entry : map.entrySet()) {
            sparseArray.put(((Field) entry.getValue()).getSafeParcelableFieldId(), entry);
        }
        sb.append('{');
        int validateObjectHeader = SafeParcelReader.validateObjectHeader(parcel);
        boolean z = false;
        while (parcel.dataPosition() < validateObjectHeader) {
            int readHeader = SafeParcelReader.readHeader(parcel);
            Entry entry2 = (Entry) sparseArray.get(SafeParcelReader.getFieldId(readHeader));
            if (entry2 != null) {
                String str = ",";
                if (z) {
                    sb.append(str);
                }
                String str2 = (String) entry2.getKey();
                Field field = (Field) entry2.getValue();
                String str3 = "\"";
                sb.append(str3);
                sb.append(str2);
                sb.append("\":");
                if (field.zacn()) {
                    switch (field.zapt) {
                        case 0:
                            zab(sb, field, zab(field, (Object) Integer.valueOf(SafeParcelReader.readInt(parcel, readHeader))));
                            break;
                        case 1:
                            zab(sb, field, zab(field, (Object) SafeParcelReader.createBigInteger(parcel, readHeader)));
                            break;
                        case 2:
                            zab(sb, field, zab(field, (Object) Long.valueOf(SafeParcelReader.readLong(parcel, readHeader))));
                            break;
                        case 3:
                            zab(sb, field, zab(field, (Object) Float.valueOf(SafeParcelReader.readFloat(parcel, readHeader))));
                            break;
                        case 4:
                            zab(sb, field, zab(field, (Object) Double.valueOf(SafeParcelReader.readDouble(parcel, readHeader))));
                            break;
                        case 5:
                            zab(sb, field, zab(field, (Object) SafeParcelReader.createBigDecimal(parcel, readHeader)));
                            break;
                        case 6:
                            zab(sb, field, zab(field, (Object) Boolean.valueOf(SafeParcelReader.readBoolean(parcel, readHeader))));
                            break;
                        case 7:
                            zab(sb, field, zab(field, (Object) SafeParcelReader.createString(parcel, readHeader)));
                            break;
                        case 8:
                        case 9:
                            zab(sb, field, zab(field, (Object) SafeParcelReader.createByteArray(parcel, readHeader)));
                            break;
                        case 10:
                            Bundle createBundle = SafeParcelReader.createBundle(parcel, readHeader);
                            HashMap hashMap = new HashMap();
                            for (String str4 : createBundle.keySet()) {
                                hashMap.put(str4, createBundle.getString(str4));
                            }
                            zab(sb, field, zab(field, (Object) hashMap));
                            break;
                        case 11:
                            throw new IllegalArgumentException("Method does not accept concrete type.");
                        default:
                            int i = field.zapt;
                            StringBuilder sb2 = new StringBuilder(36);
                            sb2.append("Unknown field out type = ");
                            sb2.append(i);
                            throw new IllegalArgumentException(sb2.toString());
                    }
                } else if (field.zapu) {
                    sb.append("[");
                    switch (field.zapt) {
                        case 0:
                            ArrayUtils.writeArray(sb, SafeParcelReader.createIntArray(parcel, readHeader));
                            break;
                        case 1:
                            ArrayUtils.writeArray(sb, (T[]) SafeParcelReader.createBigIntegerArray(parcel, readHeader));
                            break;
                        case 2:
                            ArrayUtils.writeArray(sb, SafeParcelReader.createLongArray(parcel, readHeader));
                            break;
                        case 3:
                            ArrayUtils.writeArray(sb, SafeParcelReader.createFloatArray(parcel, readHeader));
                            break;
                        case 4:
                            ArrayUtils.writeArray(sb, SafeParcelReader.createDoubleArray(parcel, readHeader));
                            break;
                        case 5:
                            ArrayUtils.writeArray(sb, (T[]) SafeParcelReader.createBigDecimalArray(parcel, readHeader));
                            break;
                        case 6:
                            ArrayUtils.writeArray(sb, SafeParcelReader.createBooleanArray(parcel, readHeader));
                            break;
                        case 7:
                            ArrayUtils.writeStringArray(sb, SafeParcelReader.createStringArray(parcel, readHeader));
                            break;
                        case 8:
                        case 9:
                        case 10:
                            throw new UnsupportedOperationException("List of type BASE64, BASE64_URL_SAFE, or STRING_MAP is not supported");
                        case 11:
                            Parcel[] createParcelArray = SafeParcelReader.createParcelArray(parcel, readHeader);
                            int length = createParcelArray.length;
                            for (int i2 = 0; i2 < length; i2++) {
                                if (i2 > 0) {
                                    sb.append(str);
                                }
                                createParcelArray[i2].setDataPosition(0);
                                zaa(sb, field.zacq(), createParcelArray[i2]);
                            }
                            break;
                        default:
                            throw new IllegalStateException("Unknown field type out.");
                    }
                    sb.append("]");
                } else {
                    switch (field.zapt) {
                        case 0:
                            sb.append(SafeParcelReader.readInt(parcel, readHeader));
                            break;
                        case 1:
                            sb.append(SafeParcelReader.createBigInteger(parcel, readHeader));
                            break;
                        case 2:
                            sb.append(SafeParcelReader.readLong(parcel, readHeader));
                            break;
                        case 3:
                            sb.append(SafeParcelReader.readFloat(parcel, readHeader));
                            break;
                        case 4:
                            sb.append(SafeParcelReader.readDouble(parcel, readHeader));
                            break;
                        case 5:
                            sb.append(SafeParcelReader.createBigDecimal(parcel, readHeader));
                            break;
                        case 6:
                            sb.append(SafeParcelReader.readBoolean(parcel, readHeader));
                            break;
                        case 7:
                            String createString = SafeParcelReader.createString(parcel, readHeader);
                            sb.append(str3);
                            sb.append(JsonUtils.escapeString(createString));
                            sb.append(str3);
                            break;
                        case 8:
                            byte[] createByteArray = SafeParcelReader.createByteArray(parcel, readHeader);
                            sb.append(str3);
                            sb.append(Base64Utils.encode(createByteArray));
                            sb.append(str3);
                            break;
                        case 9:
                            byte[] createByteArray2 = SafeParcelReader.createByteArray(parcel, readHeader);
                            sb.append(str3);
                            sb.append(Base64Utils.encodeUrlSafe(createByteArray2));
                            sb.append(str3);
                            break;
                        case 10:
                            Bundle createBundle2 = SafeParcelReader.createBundle(parcel, readHeader);
                            Set<String> keySet = createBundle2.keySet();
                            keySet.size();
                            sb.append("{");
                            boolean z2 = true;
                            for (String str5 : keySet) {
                                if (!z2) {
                                    sb.append(str);
                                }
                                sb.append(str3);
                                sb.append(str5);
                                sb.append(str3);
                                sb.append(":");
                                sb.append(str3);
                                sb.append(JsonUtils.escapeString(createBundle2.getString(str5)));
                                sb.append(str3);
                                z2 = false;
                            }
                            sb.append("}");
                            break;
                        case 11:
                            Parcel createParcel = SafeParcelReader.createParcel(parcel, readHeader);
                            createParcel.setDataPosition(0);
                            zaa(sb, field.zacq(), createParcel);
                            break;
                        default:
                            throw new IllegalStateException("Unknown field type out");
                    }
                }
                z = true;
            }
        }
        if (parcel.dataPosition() == validateObjectHeader) {
            sb.append('}');
            return;
        }
        StringBuilder sb3 = new StringBuilder(37);
        sb3.append("Overread allowed size end=");
        sb3.append(validateObjectHeader);
        throw new ParseException(sb3.toString(), parcel);
    }

    private final void zab(StringBuilder sb, Field<?, ?> field, Object obj) {
        if (field.zaps) {
            ArrayList arrayList = (ArrayList) obj;
            sb.append("[");
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                if (i != 0) {
                    sb.append(",");
                }
                zaa(sb, field.zapr, arrayList.get(i));
            }
            sb.append("]");
            return;
        }
        zaa(sb, field.zapr, obj);
    }

    private static void zaa(StringBuilder sb, int i, Object obj) {
        String str = "\"";
        switch (i) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
                sb.append(obj);
                return;
            case 7:
                sb.append(str);
                sb.append(JsonUtils.escapeString(obj.toString()));
                sb.append(str);
                return;
            case 8:
                sb.append(str);
                sb.append(Base64Utils.encode((byte[]) obj));
                sb.append(str);
                return;
            case 9:
                sb.append(str);
                sb.append(Base64Utils.encodeUrlSafe((byte[]) obj));
                sb.append(str);
                return;
            case 10:
                MapUtils.writeStringMapToJson(sb, (HashMap) obj);
                return;
            case 11:
                throw new IllegalArgumentException("Method does not accept concrete type.");
            default:
                StringBuilder sb2 = new StringBuilder(26);
                sb2.append("Unknown type = ");
                sb2.append(i);
                throw new IllegalArgumentException(sb2.toString());
        }
    }
}
