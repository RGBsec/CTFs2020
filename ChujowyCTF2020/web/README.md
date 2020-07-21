# Chujowy CTF 2020 Web Writeups
by qpwoeirut

I only solved the two super-easy beginner web challenges.
My teammates solve the rest of beginner web since they have actual web skills.

## Robots
> Tags: web, php<br>
> [https://web2.chujowyc.tf/](https://web2.chujowyc.tf/)

This was pretty simple.
Just go to [https://web2.chujowyc.tf/robots.txt](https://web2.chujowyc.tf/robots.txt).

That gets us this:
> User-agent: *<br>
> Disallow: index.php<br>
> Disallow: CQy2Z1k3J7ku7uhQ8uNTagIeLvYg1noA2f4v

We can go to [CQy2Z1k3J7ku7uhQ8uNTagIeLvYg1noA2f4v](https://web2.chujowyc.tf/CQy2Z1k3J7ku7uhQ8uNTagIeLvYg1noA2f4v) and download the flag.

`chCTF{r08075_7X7_l33k5_A_l07_0f_1nf0rmA710N}`


___

## Deployment
> Tags: web, php<br>
> [https://web1.chujowyc.tf/](https://web1.chujowyc.tf/)

By the time our team had gotten back on after the web challs were released both this and Robots had a lot of solves.
So we knew the solve was probably pretty simple.
Going the homepage just gets us some weird image.
If we look at the source for the image, we know it's from [/files/furry.jpg](https://web1.chujowyc.tf/files/furry.jpg).
If we go to [/files](https://web1.chujowyc.tf/files), then we can see the entire directory structure.
One of the files is named `flag`, so we can download it and there's our flag.

`chCTF{4U7o1Nd3x_15_b444d}`