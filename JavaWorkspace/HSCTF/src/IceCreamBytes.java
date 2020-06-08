import java.io.*;
import java.nio.file.*;
import java.util.Arrays;
import java.util.Scanner;

public class IceCreamBytes {
    public static void main(String[] args) throws IOException {
        byte[] test = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        System.out.println(Arrays.toString(test));
        System.out.println(Arrays.toString(toppings(test)));
        Path path = Paths.get("IceCreamManual.txt");
        byte[] manualBytes = Files.readAllBytes(path);

        Scanner keyboard = new Scanner(System.in);
        System.out.print("Enter the password to the ice cream machine: ");
        String userInput = keyboard.next();
        String input = userInput.substring("flag{".length(), userInput.length() - 1);
        System.out.println("You entered: " + input);
        byte[] loadedBytes = toppings(chocolateShuffle(vanillaShuffle(strawberryShuffle(input.getBytes()))));
        boolean correctPassword = true;

        byte[] correctBytes = fillMachine(manualBytes);
        System.out.println(Arrays.toString(loadedBytes));
        System.out.println(Arrays.toString(correctBytes));
        for (int i = 0; i < correctBytes.length; i++) {
            if (loadedBytes[i] != correctBytes[i]) {
                correctPassword = false;
            }
        }
        if (correctPassword) {
            System.out.println("That's right! Enjoy your ice cream!");
        } else {
            System.out.println("Uhhh that's not right.");
        }
        keyboard.close();
    }

    public static byte[] fillMachine(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[34];
        int[] intGredients = {27, 120, 79, 80, 147,
                154, 97, 8, 13, 46, 31, 54, 15, 112, 3,
                464, 116, 58, 87, 120, 139, 75, 6, 182,
                9, 153, 53, 7, 42, 23, 24, 159, 41, 110};
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = inputIceCream[intGredients[i]];
        }
        return outputIceCream;
    }

    public static byte[] strawberryShuffle(byte[] inputIceCream) {
        // reverse, [1,2,3,4,5,6,7,8,9] -> [9,8,7,6,5,4,3,2,1]
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = inputIceCream[inputIceCream.length - i - 1];
        }
        return outputIceCream;
    }

    public static byte[] vanillaShuffle(byte[] inputIceCream) {
        // inc if idx is even, dec if odd [1,2,3,4,5,6,7,8,9] -> [2,1,4,3,6,5,8,7,10]
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            if (i % 2 == 0) {
                outputIceCream[i] = (byte) (inputIceCream[i] + 1);
            } else {
                outputIceCream[i] = (byte) (inputIceCream[i] - 1);
            }
        }
        return outputIceCream;
    }

    public static byte[] chocolateShuffle(byte[] inputIceCream) {
        // shift even idxs by +2, odd idxs by -2, [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15] -> [15,4,1,6,3,8,5,10,7,12,9,14,11,2,13]
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            if (i % 2 == 0) {
                if (i > 0) {
                    outputIceCream[i] = inputIceCream[i - 2];
                } else {
                    outputIceCream[i] = inputIceCream[inputIceCream.length - 1];
                }
            } else {
                if (i < outputIceCream.length - 2) {
                    outputIceCream[i] = inputIceCream[i + 2];
                } else {
                    outputIceCream[i] = inputIceCream[1];
                }
            }
        }
        return outputIceCream;
    }

    public static byte[] toppings(byte[] inputIceCream) {
        // add topping number to each byte
        byte[] outputIceCream = new byte[inputIceCream.length];
        byte[] toppings = {4, 61, -8, -7, 58, 55,
                -8, 49, 20, 65, -7, 54, -8, 66, -9, 69,
                20, -9, -12, -4, 20, 5, 62, 3, -13, 66,
                8, 3, 56, 47, -5, 13, 1, -7,};
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = (byte) (inputIceCream[i] + toppings[i]);
        }
        return outputIceCream;
    }
}