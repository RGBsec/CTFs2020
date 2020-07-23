# CSICTF 2020 Oreo Writeup
by qpwoeirut

Category: Web<br>
Points: 100

> My nephew is a fussy eater and is only willing to eat chocolate oreo. Any other flavour and he throws a tantrum.<br>
> http://chall.csivit.com:30243

## Explanation
After poking around for a bit, I realized that Oreos are a type of cookie and checked the cookies.
This reveals a "flavour" cookie, which has a base64 value.
Decoding the base64 gets us "strawberry", so if we follow the description we can send "chocolate", base64 encoded.
This can be done with HTTPie: `http http://chall.csivit.com:30243 Cookie:flavour=Y2hvY29sYXRl`

`csictf{1ick_twi5t_dunk}`
