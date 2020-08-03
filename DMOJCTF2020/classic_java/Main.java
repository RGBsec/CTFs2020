// Java 8 is the only good Java

public class Main {
    public static void main(String[] args) {
        System.out.println(part3("0").length());
        System.out.println(part3("01").length());
        System.out.println(part3("012").length());
        System.out.println(part3("0123").length());
        System.out.println(part3("01234").length());
        System.out.println(part3("012345").length());
        System.out.println(part3("0123456").length());
        System.out.println(part3("01234567").length());
        System.out.println(part3("012345678").length());
        System.out.println(part3("0123456789").length());
        System.out.println(part3("0123"));
        System.out.println(part3("012345"));
//        String flag = args[0];
//        String returnValue = encrypt(flag);
//        for (int i = 0; i < returnValue.length(); i++) {
//            System.out.print((int)returnValue.charAt(i));
//            if (i < returnValue.length() - 1) {
//                System.out.print(" ");
//            }
//        }
    }

    public static int chunkSize = 10;

    public static String encrypt(String s) {
        String ret = "";
        for (int index = 0; index < s.length(); index += chunkSize) { // encrypted in chunks of 10
            String t = "";
            for (int place = 0; place < chunkSize && index + place < s.length(); place++) {
                t += s.charAt(index + place);
            }
            if (Math.random() < 0.5) {
                t = part1(t);
            } else {
                t = part2(t);
            }
            ret += part3(t); // rev part3 first
        }
        return ret;
    }

    public static String part1(String s) {
        if (s.length() == 0) {
            return "";
        }
        String ret = "" + s.charAt(0);
        for (int index = 1; index < s.length(); index++) {
            ret += (char)((int)s.charAt(index) ^ (int)s.charAt(index - 1));
        }
        return ret;
    }

    public static String part2(String s) {
        if (s.length() == 0) {
            return "";
        }
        String ret = "";
        for (int index = 1; index < s.length(); index++) {
            ret += (char)((int)s.charAt(index) ^ s.charAt(0));
        }
        return part2(ret) + s.charAt(0); // aaaaaaa this is recursive (reading comprehension 9000)
    }

    public static String part3(String s) {
        if (s.length() == 0) {
            return "";
        }
        // s[len(s)//5:] + s[:len(s)//2] + part3(s[:len(s)//2])
        return s.substring(s.length() / 5, s.length()) + s.substring(0, s.length() / 2) + part3(s.substring(0, s.length() / 2));
    }
}
