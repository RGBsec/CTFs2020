# NACTF 2020 Writeups: Inspect, Missing Image, Forms, Login

## Inspect
Points: 50
> Lola's new to website-building. Having just learned HTML and CSS, she built this site and embedded some dark secrets. I wonder where I could find them.<br>
> http://inspect.challenges.nactf.com/<br>
> -mcantillon

Inspect the stylesheet: `nactf{1nspect1ng_sp13s_4_lyf3}`


## Missing Image
Points: 75
> Max has been trying to add a picture to his first website. He uploaded the image to the server, but unfortunately, the image doesn't seem to be loading. I think he might be looking in the wrong subdomain...<br>
> https://hidden.challenges.nactf.com/<br>
> -izhang05

Go to https://hidden.challenges.nactf.com/flag.png: `nactf{h1dd3n_1mag3s}`


## Forms
Points: 125
> Skywalker has created 1000 login forms and only managed to make one of them work. Find the right one and login! He also went a bit crazy with the colors for some reason.<br>
> https://forms.challenges.nactf.com/ <br>
> -izhang05

Start by finding the right button with CSS selector `button:not([value="false"])`.
Then we see that clicking will invoke a `verify` function, and we from that we know the username is `admin` and the password is `password123`.
Flag: `nactf{cl13n75_ar3_3v11}`


## Calculator
Points: 150
> Kevin has created a cool calculator that can perform almost any mathematical operation! It seems that he might have done this the lazy way though... He's also hidden a flag variable somewhere in the code.<br>
> https://calculator.challenges.nactf.com/<br>
> -izhang05

Hint:
> What's the easiest way to evaluate user input?

Just have it evaluate `$flag`: `nactf{ev1l_eval}`


## Cookie Recipe
Points: 150
> Arjun owns a cookie shop serving warm, delicious, oven-baked cookies. He sent me his ages-old family recipe dating back four generations through this link, but, for some reason, I can't get the recipe. Only cookie lovers are allowed!<br>
> https://cookies.challenges.nactf.com/index.php<br>
> -izhang05

Hint:
>Arjun baked a cookie as an offering, but he accidently placed it on the front page.

Change the cookie path to `/` and the expiration time to something far in the future.
Then login with username=`admin` and password=`password`.<br>
Flag: `nactf{c00kie_m0nst3r_5bxr16o0z}`


## Login
Points: 175
> Vyom has learned his lesson about client side authentication and his soggy croutons will now be protected. There's no way you can log in to this secure portal!<br>
> https://login.challenges.nactf.com/ <br>
> -izhang05

Hint:
> https://xkcd.com/327/

The hint points us to SQLi, and some messing around gets us a payload with username=`' OR 1=1--'` and password=`'--'`<br>
Flag: `nactf{sQllllllll_1m5qpr8x}`