package androidx.vectordrawable.graphics.drawable;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.Resources.NotFoundException;
import android.content.res.Resources.Theme;
import android.content.res.XmlResourceParser;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.util.Xml;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.AnimationUtils;
import android.view.animation.AnticipateInterpolator;
import android.view.animation.AnticipateOvershootInterpolator;
import android.view.animation.BounceInterpolator;
import android.view.animation.CycleInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.LinearInterpolator;
import android.view.animation.OvershootInterpolator;
import androidx.interpolator.view.animation.FastOutLinearInInterpolator;
import androidx.interpolator.view.animation.FastOutSlowInInterpolator;
import androidx.interpolator.view.animation.LinearOutSlowInInterpolator;
import java.io.IOException;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

public class AnimationUtilsCompat {
    public static Interpolator loadInterpolator(Context context, int id) throws NotFoundException {
        if (VERSION.SDK_INT >= 21) {
            return AnimationUtils.loadInterpolator(context, id);
        }
        XmlResourceParser parser = null;
        String str = "Can't load animation resource ID #0x";
        if (id == 17563663) {
            try {
                FastOutLinearInInterpolator fastOutLinearInInterpolator = new FastOutLinearInInterpolator();
                if (parser != null) {
                    parser.close();
                }
                return fastOutLinearInInterpolator;
            } catch (XmlPullParserException ex) {
                StringBuilder sb = new StringBuilder();
                sb.append(str);
                sb.append(Integer.toHexString(id));
                NotFoundException rnf = new NotFoundException(sb.toString());
                rnf.initCause(ex);
                throw rnf;
            } catch (IOException ex2) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append(str);
                sb2.append(Integer.toHexString(id));
                NotFoundException rnf2 = new NotFoundException(sb2.toString());
                rnf2.initCause(ex2);
                throw rnf2;
            } catch (Throwable th) {
                if (parser != null) {
                    parser.close();
                }
                throw th;
            }
        } else if (id == 17563661) {
            FastOutSlowInInterpolator fastOutSlowInInterpolator = new FastOutSlowInInterpolator();
            if (parser != null) {
                parser.close();
            }
            return fastOutSlowInInterpolator;
        } else if (id == 17563662) {
            LinearOutSlowInInterpolator linearOutSlowInInterpolator = new LinearOutSlowInInterpolator();
            if (parser != null) {
                parser.close();
            }
            return linearOutSlowInInterpolator;
        } else {
            XmlResourceParser parser2 = context.getResources().getAnimation(id);
            Interpolator createInterpolatorFromXml = createInterpolatorFromXml(context, context.getResources(), context.getTheme(), parser2);
            if (parser2 != null) {
                parser2.close();
            }
            return createInterpolatorFromXml;
        }
    }

    private static Interpolator createInterpolatorFromXml(Context context, Resources res, Theme theme, XmlPullParser parser) throws XmlPullParserException, IOException {
        Interpolator interpolator = null;
        int depth = parser.getDepth();
        while (true) {
            int next = parser.next();
            int type = next;
            if ((next != 3 || parser.getDepth() > depth) && type != 1) {
                if (type == 2) {
                    AttributeSet attrs = Xml.asAttributeSet(parser);
                    String name = parser.getName();
                    if (name.equals("linearInterpolator")) {
                        interpolator = new LinearInterpolator();
                    } else if (name.equals("accelerateInterpolator")) {
                        interpolator = new AccelerateInterpolator(context, attrs);
                    } else if (name.equals("decelerateInterpolator")) {
                        interpolator = new DecelerateInterpolator(context, attrs);
                    } else if (name.equals("accelerateDecelerateInterpolator")) {
                        interpolator = new AccelerateDecelerateInterpolator();
                    } else if (name.equals("cycleInterpolator")) {
                        interpolator = new CycleInterpolator(context, attrs);
                    } else if (name.equals("anticipateInterpolator")) {
                        interpolator = new AnticipateInterpolator(context, attrs);
                    } else if (name.equals("overshootInterpolator")) {
                        interpolator = new OvershootInterpolator(context, attrs);
                    } else if (name.equals("anticipateOvershootInterpolator")) {
                        interpolator = new AnticipateOvershootInterpolator(context, attrs);
                    } else if (name.equals("bounceInterpolator")) {
                        interpolator = new BounceInterpolator();
                    } else if (name.equals("pathInterpolator")) {
                        interpolator = new PathInterpolatorCompat(context, attrs, parser);
                    } else {
                        StringBuilder sb = new StringBuilder();
                        sb.append("Unknown interpolator name: ");
                        sb.append(parser.getName());
                        throw new RuntimeException(sb.toString());
                    }
                }
            }
        }
        return interpolator;
    }

    private AnimationUtilsCompat() {
    }
}
