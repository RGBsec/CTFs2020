package com.houseplant;

import java.util.*;

public class Main {
    public static int[] realflag = {9, 4, 23, 8, 17, 1, 18, 0, 13, 7, 2, 20, 16, 10, 22, 12, 19, 6, 15, 21, 3, 14, 5, 11};
    public static int[] therealflag = {20, 16, 12, 9, 6, 15, 21, 3, 18, 0, 13, 7, 1, 4, 23, 8, 17, 2, 10, 22, 19, 11, 14, 5};
    public static HashMap<Integer, Character> theflags = new HashMap<>();
    public static HashMap<Integer, Character> theflags0 = new HashMap<>();
    public static HashMap<Integer, Character> theflags1 = new HashMap<>();
    public static HashMap<Integer, Character> theflags2 = new HashMap<>();

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter flag: ");
//        String userInput = scanner.next();
        String userInput = "rtcp{h3?)s_4_c0stly_fl4g_4yeu}";
        String input = userInput.substring("rtcp{".length(), userInput.length() - 1);
        System.out.println(input);
        if (check(input)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }

    public static boolean check(String input) {
        String flag = "ow0_wh4t_4_h4ckr_y0u_4r3";
        createMap(theflags, input, true);
        createMap(theflags0, flag, false);
        createMap(theflags1, input, false);
        createMap(theflags2, flag, true);
        System.out.println(theflags);
        System.out.println(theflags0);
        System.out.println(theflags1);
        System.out.println(theflags2);
        String theflag = "";
        String thefinalflag = "";
        if (input.length() != flag.length()) {
            System.out.println("Wrong length");
            System.out.println(flag.length());
            return false;
        }
        //rtcp{h3r3s_a_fr33_fl4g!}
        int i = 0;
        for (; i < input.length() - 3; i++) {
            theflag += theflags.get(i);
        }
        System.out.println(theflag);
        for (; i < input.length(); i++) {
            theflag += theflags1.get(i);
        }
        System.out.println(theflag);
        System.out.println(theflag.length());
        for (int p = 0; p < theflag.length(); p++) {
            thefinalflag += (char) ((int) (theflags0.get(p)) + (int) (theflag.charAt(p)));
        }
        for (int p = 0; p < theflag.length(); p++) {
            if ((int) (thefinalflag.charAt(p)) > 145 && (int) (thefinalflag.charAt(p)) < 157) {
                // add 10 to character at p
                thefinalflag = thefinalflag.substring(0, p) + (char) ((int) (thefinalflag.charAt(p) + 10)) + thefinalflag.substring(p + 1);
            }
        }
        String correct = "ì¨ ¢«¢¥Ç©© ÂëÏãÒËãhÔÊ";
        System.out.println(thefinalflag);
        for (int j=0; j<thefinalflag.length(); j++) {
            if (correct.charAt(j) != thefinalflag.charAt(j)) {
                System.out.println(j + " " + (int)thefinalflag.charAt(j) + " " + (int)correct.charAt(j));
            }
        }
        System.out.println();
        return thefinalflag.equals("ì¨ ¢«¢¥Ç©© ÂëÏãÒËãhÔÊ");
    }

    public static void createMap(HashMap owo, String input, boolean uwu) {
        if (uwu) {
            for (int i = 0; i < input.length(); i++) {
                owo.put(realflag[i], input.charAt(i));
            }
        } else {
            for (int i = 0; i < input.length(); i++) {
                owo.put(therealflag[i], input.charAt(i));
            }
        }
    }
}