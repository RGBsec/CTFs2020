import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class CrackMe {
   public static void main(String[] var0) {
      Scanner scanner = new Scanner(System.in);
      System.out.println("What is the flag?");
      String input = scanner.nextLine();
      System.out.println(input.length());
      if (input.length() != 22) {
         System.out.println("Not the flag :(");
      } else {
         char[] copy = new char[input.length()];

         int i;
         for(i = 0; i < input.length(); ++i) {
            copy[i] = input.charAt(i);
         }
         System.out.println(copy);

         // reverse
         for(i = 0; i < input.length() / 2; ++i) {
            char tmp = copy[input.length() - i - 1];
            copy[input.length() - i - 1] = copy[i];
            copy[i] = tmp;
         }
         System.out.println(copy);

         // shuffle
         int[] perm = new int[]{19, 17, 15, 6, 9, 4, 18, 8, 16, 13, 21, 11, 7, 0, 12, 3, 5, 2, 20, 14, 10, 1};
         int[] shuffled = new int[copy.length];

         for(int idx = perm.length - 1; idx >= 0; --idx) {
            shuffled[idx] = copy[perm[idx]];
         }
         System.out.println(Arrays.toString(shuffled));

         Random rand = new Random();
         rand.setSeed(431289L);
         int[] res = new int[input.length()];

         for(int idx = 0; idx < input.length(); ++idx) {
//            res[idx] = shuffled[idx] ^ rand.nextInt(idx + 1);
            System.out.println(rand.nextInt(idx + 1));
         }

         String enc = "";

         for(int idx = 0; idx < res.length; ++idx) {
            enc = enc + res[idx] + ".";
         }

         if (enc.equals("97.122.54.50.93.66.99.117.75.51.101.78.104.119.90.53.94.36.102.84.40.69.")) {
            System.out.println("Congrats! You got the flag!");
         } else {
            System.out.println("Not the flag :(");
         }

      }
   }
}
