# NACTF 2020 Writeups: World Trip

Points: 300

> Will has been travelling the world! Here's a list of the coordinates of the places he's been to. There might be a secret message hidden in the first letter of all of the countries.<br>
> Note: The flag is all uppercase without spaces or "_"<br>
> -izhang05

Hint:
> This would be really tedious to do by hand...

Hint:
> The last part of the flag is just random characters

## Explanation
The task is pretty clear here.We need to find the country each coordinate is located in.
I spent some time messing around on some python packages but I couldn't get any of them working.
I ended up writing a script to scrape the countries off of Google Maps client-side.
This didn't take too long to do in Selenium, but the formats weren't completely consistent.
So I had to go through manually and fix all the incorrect formats.
Fortunately there were only 194 different coordinates so it didn't take too long.

Flag: `nactf{IHOPEYOUENJOYEDGOINGONTHATREALLYLONGGLOBALTOURIBOFAIQFUSETZOROPZNQTLENFLFSEMOGMHDBEEIZOIUOCGSLCDYMQYIRLBZKNHHFGBPDIVNBUQQYPDCQIAVDYTRFOCESEQUOUUMSKYJOVKVJGMRGNATNIRESHRKHCEDHHZYQRZVOGCHSBAYUBTRU}`