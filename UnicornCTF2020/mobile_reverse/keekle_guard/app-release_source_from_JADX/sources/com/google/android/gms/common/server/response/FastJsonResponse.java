package com.google.android.gms.common.server.response;

import android.os.Parcel;
import android.util.Log;
import com.google.android.gms.common.internal.Objects;
import com.google.android.gms.common.internal.Objects.ToStringHelper;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;
import com.google.android.gms.common.server.converter.zaa;
import com.google.android.gms.common.util.Base64Utils;
import com.google.android.gms.common.util.JsonUtils;
import com.google.android.gms.common.util.MapUtils;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public abstract class FastJsonResponse {

    public static class Field<I, O> extends AbstractSafeParcelable {
        public static final zai CREATOR = new zai();
        private final int zalf;
        protected final int zapr;
        protected final boolean zaps;
        protected final int zapt;
        protected final boolean zapu;
        protected final String zapv;
        protected final int zapw;
        protected final Class<? extends FastJsonResponse> zapx;
        private final String zapy;
        private zak zapz;
        /* access modifiers changed from: private */
        public FieldConverter<I, O> zaqa;

        Field(int i, int i2, boolean z, int i3, boolean z2, String str, int i4, String str2, zaa zaa) {
            this.zalf = i;
            this.zapr = i2;
            this.zaps = z;
            this.zapt = i3;
            this.zapu = z2;
            this.zapv = str;
            this.zapw = i4;
            if (str2 == null) {
                this.zapx = null;
                this.zapy = null;
            } else {
                this.zapx = SafeParcelResponse.class;
                this.zapy = str2;
            }
            if (zaa == null) {
                this.zaqa = null;
            } else {
                this.zaqa = zaa.zaci();
            }
        }

        private Field(int i, boolean z, int i2, boolean z2, String str, int i3, Class<? extends FastJsonResponse> cls, FieldConverter<I, O> fieldConverter) {
            this.zalf = 1;
            this.zapr = i;
            this.zaps = z;
            this.zapt = i2;
            this.zapu = z2;
            this.zapv = str;
            this.zapw = i3;
            this.zapx = cls;
            if (cls == null) {
                this.zapy = null;
            } else {
                this.zapy = cls.getCanonicalName();
            }
            this.zaqa = fieldConverter;
        }

        public final Field<I, O> zacl() {
            Field field = new Field(this.zalf, this.zapr, this.zaps, this.zapt, this.zapu, this.zapv, this.zapw, this.zapy, zaco());
            return field;
        }

        public int getSafeParcelableFieldId() {
            return this.zapw;
        }

        private final String zacm() {
            String str = this.zapy;
            if (str == null) {
                return null;
            }
            return str;
        }

        public final boolean zacn() {
            return this.zaqa != null;
        }

        public final void zaa(zak zak) {
            this.zapz = zak;
        }

        private final zaa zaco() {
            FieldConverter<I, O> fieldConverter = this.zaqa;
            if (fieldConverter == null) {
                return null;
            }
            return zaa.zaa(fieldConverter);
        }

        public final FastJsonResponse zacp() throws InstantiationException, IllegalAccessException {
            Class<? extends FastJsonResponse> cls = this.zapx;
            if (cls != SafeParcelResponse.class) {
                return (FastJsonResponse) cls.newInstance();
            }
            Preconditions.checkNotNull(this.zapz, "The field mapping dictionary must be set if the concrete type is a SafeParcelResponse object.");
            return new SafeParcelResponse(this.zapz, this.zapy);
        }

        public final Map<String, Field<?, ?>> zacq() {
            Preconditions.checkNotNull(this.zapy);
            Preconditions.checkNotNull(this.zapz);
            return this.zapz.zai(this.zapy);
        }

        public final O convert(I i) {
            return this.zaqa.convert(i);
        }

        public final I convertBack(O o) {
            return this.zaqa.convertBack(o);
        }

        public static Field<Integer, Integer> forInteger(String str, int i) {
            Field field = new Field(0, false, 0, false, str, i, null, null);
            return field;
        }

        public static Field<Long, Long> forLong(String str, int i) {
            Field field = new Field(2, false, 2, false, str, i, null, null);
            return field;
        }

        public static Field<Float, Float> forFloat(String str, int i) {
            Field field = new Field(3, false, 3, false, str, i, null, null);
            return field;
        }

        public static Field<Double, Double> forDouble(String str, int i) {
            Field field = new Field(4, false, 4, false, str, i, null, null);
            return field;
        }

        public static Field<Boolean, Boolean> forBoolean(String str, int i) {
            Field field = new Field(6, false, 6, false, str, i, null, null);
            return field;
        }

        public static Field<String, String> forString(String str, int i) {
            Field field = new Field(7, false, 7, false, str, i, null, null);
            return field;
        }

        public static Field<ArrayList<String>, ArrayList<String>> forStrings(String str, int i) {
            Field field = new Field(7, true, 7, true, str, i, null, null);
            return field;
        }

        public static Field<byte[], byte[]> forBase64(String str, int i) {
            Field field = new Field(8, false, 8, false, str, i, null, null);
            return field;
        }

        public static <T extends FastJsonResponse> Field<T, T> forConcreteType(String str, int i, Class<T> cls) {
            Field field = new Field(11, false, 11, false, str, i, cls, null);
            return field;
        }

        public static <T extends FastJsonResponse> Field<ArrayList<T>, ArrayList<T>> forConcreteTypeArray(String str, int i, Class<T> cls) {
            Field field = new Field(11, true, 11, true, str, i, cls, null);
            return field;
        }

        public static Field withConverter(String str, int i, FieldConverter<?, ?> fieldConverter, boolean z) {
            Field field = new Field(fieldConverter.zacj(), z, fieldConverter.zack(), false, str, i, null, fieldConverter);
            return field;
        }

        public void writeToParcel(Parcel parcel, int i) {
            int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
            SafeParcelWriter.writeInt(parcel, 1, this.zalf);
            SafeParcelWriter.writeInt(parcel, 2, this.zapr);
            SafeParcelWriter.writeBoolean(parcel, 3, this.zaps);
            SafeParcelWriter.writeInt(parcel, 4, this.zapt);
            SafeParcelWriter.writeBoolean(parcel, 5, this.zapu);
            SafeParcelWriter.writeString(parcel, 6, this.zapv, false);
            SafeParcelWriter.writeInt(parcel, 7, getSafeParcelableFieldId());
            SafeParcelWriter.writeString(parcel, 8, zacm(), false);
            SafeParcelWriter.writeParcelable(parcel, 9, zaco(), i, false);
            SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
        }

        public String toString() {
            String str = "typeIn";
            String str2 = "typeInArray";
            String str3 = "typeOut";
            String str4 = "typeOutArray";
            String str5 = "outputFieldName";
            String str6 = "safeParcelFieldId";
            String str7 = "concreteTypeName";
            ToStringHelper add = Objects.toStringHelper(this).add("versionCode", Integer.valueOf(this.zalf)).add(str, Integer.valueOf(this.zapr)).add(str2, Boolean.valueOf(this.zaps)).add(str3, Integer.valueOf(this.zapt)).add(str4, Boolean.valueOf(this.zapu)).add(str5, this.zapv).add(str6, Integer.valueOf(this.zapw)).add(str7, zacm());
            Class<? extends FastJsonResponse> cls = this.zapx;
            if (cls != null) {
                add.add("concreteType.class", cls.getCanonicalName());
            }
            FieldConverter<I, O> fieldConverter = this.zaqa;
            if (fieldConverter != null) {
                add.add("converterName", fieldConverter.getClass().getCanonicalName());
            }
            return add.toString();
        }
    }

    public interface FieldConverter<I, O> {
        O convert(I i);

        I convertBack(O o);

        int zacj();

        int zack();
    }

    public abstract Map<String, Field<?, ?>> getFieldMappings();

    /* access modifiers changed from: protected */
    public abstract Object getValueObject(String str);

    /* access modifiers changed from: protected */
    public abstract boolean isPrimitiveFieldSet(String str);

    /* access modifiers changed from: protected */
    public boolean isFieldSet(Field field) {
        if (field.zapt != 11) {
            return isPrimitiveFieldSet(field.zapv);
        }
        if (field.zapu) {
            String str = field.zapv;
            throw new UnsupportedOperationException("Concrete type arrays not supported");
        }
        String str2 = field.zapv;
        throw new UnsupportedOperationException("Concrete types not supported");
    }

    private final <I, O> void zaa(Field<I, O> field, I i) {
        String str = field.zapv;
        Object convert = field.convert(i);
        switch (field.zapt) {
            case 0:
                if (zaa(str, (O) convert)) {
                    setIntegerInternal(field, str, ((Integer) convert).intValue());
                    break;
                }
                break;
            case 1:
                zaa(field, str, (BigInteger) convert);
                return;
            case 2:
                if (zaa(str, (O) convert)) {
                    setLongInternal(field, str, ((Long) convert).longValue());
                    return;
                }
                break;
            case 4:
                if (zaa(str, (O) convert)) {
                    zaa(field, str, ((Double) convert).doubleValue());
                    return;
                }
                break;
            case 5:
                zaa(field, str, (BigDecimal) convert);
                return;
            case 6:
                if (zaa(str, (O) convert)) {
                    setBooleanInternal(field, str, ((Boolean) convert).booleanValue());
                    return;
                }
                break;
            case 7:
                setStringInternal(field, str, (String) convert);
                return;
            case 8:
            case 9:
                if (zaa(str, (O) convert)) {
                    setDecodedBytesInternal(field, str, (byte[]) convert);
                    return;
                }
                break;
            default:
                int i2 = field.zapt;
                StringBuilder sb = new StringBuilder(44);
                sb.append("Unsupported type for conversion: ");
                sb.append(i2);
                throw new IllegalStateException(sb.toString());
        }
    }

    protected static <O, I> I zab(Field<I, O> field, Object obj) {
        return field.zaqa != null ? field.convertBack(obj) : obj;
    }

    public final <O> void zaa(Field<Integer, O> field, int i) {
        if (field.zaqa != null) {
            zaa(field, (I) Integer.valueOf(i));
        } else {
            setIntegerInternal(field, field.zapv, i);
        }
    }

    public final <O> void zaa(Field<ArrayList<Integer>, O> field, ArrayList<Integer> arrayList) {
        if (field.zaqa != null) {
            zaa(field, (I) arrayList);
        } else {
            zaa(field, field.zapv, arrayList);
        }
    }

    public final <O> void zaa(Field<BigInteger, O> field, BigInteger bigInteger) {
        if (field.zaqa != null) {
            zaa(field, (I) bigInteger);
        } else {
            zaa(field, field.zapv, bigInteger);
        }
    }

    public final <O> void zab(Field<ArrayList<BigInteger>, O> field, ArrayList<BigInteger> arrayList) {
        if (field.zaqa != null) {
            zaa(field, (I) arrayList);
        } else {
            zab(field, field.zapv, arrayList);
        }
    }

    public final <O> void zaa(Field<Long, O> field, long j) {
        if (field.zaqa != null) {
            zaa(field, (I) Long.valueOf(j));
        } else {
            setLongInternal(field, field.zapv, j);
        }
    }

    public final <O> void zac(Field<ArrayList<Long>, O> field, ArrayList<Long> arrayList) {
        if (field.zaqa != null) {
            zaa(field, (I) arrayList);
        } else {
            zac(field, field.zapv, arrayList);
        }
    }

    public final <O> void zaa(Field<Float, O> field, float f) {
        if (field.zaqa != null) {
            zaa(field, (I) Float.valueOf(f));
        } else {
            zaa(field, field.zapv, f);
        }
    }

    public final <O> void zad(Field<ArrayList<Float>, O> field, ArrayList<Float> arrayList) {
        if (field.zaqa != null) {
            zaa(field, (I) arrayList);
        } else {
            zad(field, field.zapv, arrayList);
        }
    }

    public final <O> void zaa(Field<Double, O> field, double d) {
        if (field.zaqa != null) {
            zaa(field, (I) Double.valueOf(d));
        } else {
            zaa(field, field.zapv, d);
        }
    }

    public final <O> void zae(Field<ArrayList<Double>, O> field, ArrayList<Double> arrayList) {
        if (field.zaqa != null) {
            zaa(field, (I) arrayList);
        } else {
            zae(field, field.zapv, arrayList);
        }
    }

    public final <O> void zaa(Field<BigDecimal, O> field, BigDecimal bigDecimal) {
        if (field.zaqa != null) {
            zaa(field, (I) bigDecimal);
        } else {
            zaa(field, field.zapv, bigDecimal);
        }
    }

    public final <O> void zaf(Field<ArrayList<BigDecimal>, O> field, ArrayList<BigDecimal> arrayList) {
        if (field.zaqa != null) {
            zaa(field, (I) arrayList);
        } else {
            zaf(field, field.zapv, arrayList);
        }
    }

    public final <O> void zaa(Field<Boolean, O> field, boolean z) {
        if (field.zaqa != null) {
            zaa(field, (I) Boolean.valueOf(z));
        } else {
            setBooleanInternal(field, field.zapv, z);
        }
    }

    public final <O> void zag(Field<ArrayList<Boolean>, O> field, ArrayList<Boolean> arrayList) {
        if (field.zaqa != null) {
            zaa(field, (I) arrayList);
        } else {
            zag(field, field.zapv, arrayList);
        }
    }

    public final <O> void zaa(Field<String, O> field, String str) {
        if (field.zaqa != null) {
            zaa(field, (I) str);
        } else {
            setStringInternal(field, field.zapv, str);
        }
    }

    public final <O> void zah(Field<ArrayList<String>, O> field, ArrayList<String> arrayList) {
        if (field.zaqa != null) {
            zaa(field, (I) arrayList);
        } else {
            setStringsInternal(field, field.zapv, arrayList);
        }
    }

    public final <O> void zaa(Field<byte[], O> field, byte[] bArr) {
        if (field.zaqa != null) {
            zaa(field, (I) bArr);
        } else {
            setDecodedBytesInternal(field, field.zapv, bArr);
        }
    }

    public final <O> void zaa(Field<Map<String, String>, O> field, Map<String, String> map) {
        if (field.zaqa != null) {
            zaa(field, (I) map);
        } else {
            zaa(field, field.zapv, map);
        }
    }

    /* access modifiers changed from: protected */
    public void setIntegerInternal(Field<?, ?> field, String str, int i) {
        throw new UnsupportedOperationException("Integer not supported");
    }

    /* access modifiers changed from: protected */
    public void zaa(Field<?, ?> field, String str, ArrayList<Integer> arrayList) {
        throw new UnsupportedOperationException("Integer list not supported");
    }

    /* access modifiers changed from: protected */
    public void zaa(Field<?, ?> field, String str, BigInteger bigInteger) {
        throw new UnsupportedOperationException("BigInteger not supported");
    }

    /* access modifiers changed from: protected */
    public void zab(Field<?, ?> field, String str, ArrayList<BigInteger> arrayList) {
        throw new UnsupportedOperationException("BigInteger list not supported");
    }

    /* access modifiers changed from: protected */
    public void setLongInternal(Field<?, ?> field, String str, long j) {
        throw new UnsupportedOperationException("Long not supported");
    }

    /* access modifiers changed from: protected */
    public void zac(Field<?, ?> field, String str, ArrayList<Long> arrayList) {
        throw new UnsupportedOperationException("Long list not supported");
    }

    /* access modifiers changed from: protected */
    public void zaa(Field<?, ?> field, String str, float f) {
        throw new UnsupportedOperationException("Float not supported");
    }

    /* access modifiers changed from: protected */
    public void zad(Field<?, ?> field, String str, ArrayList<Float> arrayList) {
        throw new UnsupportedOperationException("Float list not supported");
    }

    /* access modifiers changed from: protected */
    public void zaa(Field<?, ?> field, String str, double d) {
        throw new UnsupportedOperationException("Double not supported");
    }

    /* access modifiers changed from: protected */
    public void zae(Field<?, ?> field, String str, ArrayList<Double> arrayList) {
        throw new UnsupportedOperationException("Double list not supported");
    }

    /* access modifiers changed from: protected */
    public void zaa(Field<?, ?> field, String str, BigDecimal bigDecimal) {
        throw new UnsupportedOperationException("BigDecimal not supported");
    }

    /* access modifiers changed from: protected */
    public void zaf(Field<?, ?> field, String str, ArrayList<BigDecimal> arrayList) {
        throw new UnsupportedOperationException("BigDecimal list not supported");
    }

    /* access modifiers changed from: protected */
    public void setBooleanInternal(Field<?, ?> field, String str, boolean z) {
        throw new UnsupportedOperationException("Boolean not supported");
    }

    /* access modifiers changed from: protected */
    public void zag(Field<?, ?> field, String str, ArrayList<Boolean> arrayList) {
        throw new UnsupportedOperationException("Boolean list not supported");
    }

    /* access modifiers changed from: protected */
    public void setStringInternal(Field<?, ?> field, String str, String str2) {
        throw new UnsupportedOperationException("String not supported");
    }

    /* access modifiers changed from: protected */
    public void setStringsInternal(Field<?, ?> field, String str, ArrayList<String> arrayList) {
        throw new UnsupportedOperationException("String list not supported");
    }

    /* access modifiers changed from: protected */
    public void setDecodedBytesInternal(Field<?, ?> field, String str, byte[] bArr) {
        throw new UnsupportedOperationException("byte[] not supported");
    }

    /* access modifiers changed from: protected */
    public void zaa(Field<?, ?> field, String str, Map<String, String> map) {
        throw new UnsupportedOperationException("String map not supported");
    }

    private static <O> boolean zaa(String str, O o) {
        if (o != null) {
            return true;
        }
        String str2 = "FastJsonResponse";
        if (Log.isLoggable(str2, 6)) {
            StringBuilder sb = new StringBuilder(String.valueOf(str).length() + 58);
            sb.append("Output field (");
            sb.append(str);
            sb.append(") has a null value, but expected a primitive");
            Log.e(str2, sb.toString());
        }
        return false;
    }

    public <T extends FastJsonResponse> void addConcreteTypeInternal(Field<?, ?> field, String str, T t) {
        throw new UnsupportedOperationException("Concrete type not supported");
    }

    public <T extends FastJsonResponse> void addConcreteTypeArrayInternal(Field<?, ?> field, String str, ArrayList<T> arrayList) {
        throw new UnsupportedOperationException("Concrete type array not supported");
    }

    public String toString() {
        Map fieldMappings = getFieldMappings();
        StringBuilder sb = new StringBuilder(100);
        for (String str : fieldMappings.keySet()) {
            Field field = (Field) fieldMappings.get(str);
            if (isFieldSet(field)) {
                Object zab = zab(field, getFieldValue(field));
                String str2 = ",";
                if (sb.length() == 0) {
                    sb.append("{");
                } else {
                    sb.append(str2);
                }
                String str3 = "\"";
                sb.append(str3);
                sb.append(str);
                sb.append("\":");
                if (zab != null) {
                    switch (field.zapt) {
                        case 8:
                            sb.append(str3);
                            sb.append(Base64Utils.encode((byte[]) zab));
                            sb.append(str3);
                            break;
                        case 9:
                            sb.append(str3);
                            sb.append(Base64Utils.encodeUrlSafe((byte[]) zab));
                            sb.append(str3);
                            break;
                        case 10:
                            MapUtils.writeStringMapToJson(sb, (HashMap) zab);
                            break;
                        default:
                            if (!field.zaps) {
                                zaa(sb, field, zab);
                                break;
                            } else {
                                ArrayList arrayList = (ArrayList) zab;
                                sb.append("[");
                                int size = arrayList.size();
                                for (int i = 0; i < size; i++) {
                                    if (i > 0) {
                                        sb.append(str2);
                                    }
                                    Object obj = arrayList.get(i);
                                    if (obj != null) {
                                        zaa(sb, field, obj);
                                    }
                                }
                                sb.append("]");
                                break;
                            }
                    }
                } else {
                    sb.append("null");
                }
            }
        }
        if (sb.length() > 0) {
            sb.append("}");
        } else {
            sb.append("{}");
        }
        return sb.toString();
    }

    /* access modifiers changed from: protected */
    public Object getFieldValue(Field field) {
        String str = field.zapv;
        if (field.zapx == null) {
            return getValueObject(field.zapv);
        }
        Preconditions.checkState(getValueObject(field.zapv) == null, "Concrete field shouldn't be value object: %s", field.zapv);
        boolean z = field.zapu;
        try {
            char upperCase = Character.toUpperCase(str.charAt(0));
            String substring = str.substring(1);
            StringBuilder sb = new StringBuilder(String.valueOf(substring).length() + 4);
            sb.append("get");
            sb.append(upperCase);
            sb.append(substring);
            return getClass().getMethod(sb.toString(), new Class[0]).invoke(this, new Object[0]);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void zaa(StringBuilder sb, Field field, Object obj) {
        if (field.zapr == 11) {
            sb.append(((FastJsonResponse) field.zapx.cast(obj)).toString());
        } else if (field.zapr == 7) {
            String str = "\"";
            sb.append(str);
            sb.append(JsonUtils.escapeString((String) obj));
            sb.append(str);
        } else {
            sb.append(obj);
        }
    }
}
