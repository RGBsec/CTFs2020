You didn't think it would be this easy, did you?

https://www.youtube.com/watch?v=VVdmmN0su6E#t=11m32s

Maybe try running `./mutool draw -r 300 -o rendered.png` on this PDF

```
$ docker run -ti --rm -w /workdir/ --mount type=bind,source="$PWD",target=/workdir ubuntu:bionic ./mutool 
```
