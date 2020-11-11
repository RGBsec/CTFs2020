# b01lers bootcamp CTF 2020 Writeup: Crypto World

## Warmups
```
LEVEL 1: Add 1 and 1.

> ans 2
CORRECT! Your flag is FAKE{c4f5f0683f231000c99f8c53}

LEVEL 2: Subtract 5 from 3.

> ans -2
CORRECT! Your flag is FAKE{4ef723be81cef98dc64f61fb}

LEVEL 3: put the numbers 3, 1, 7 into increasing order.

> ans 1 3 7
CORRECT! Your flag is FAKE{3841ca099e4c5380e5d51161}

COMPLETED all levels in this area.
```
This seems to be at the top right corner - we are unable to go north or east.<br>
Going west gets us to location B

## B
```
> w
You went west.

Passing by a small town, you meet a scholar, and you two walk together for a
while. He rambles about a manuscript that, he says, claims the preposterous 
idea that one equation could nail down two variables simultaneously. Since 
you show enough interest, he lets you copy a few puzzles from the book.

LEVEL 1: find integers x and y that satisfy 123*x + 179*y = 1

> ans -16 11
CORRECT! Your flag is mini{B1_485a3ae14ebb98e8ccc855b3}

LEVEL 2: find integers x and y that satisfy 5419637592*x + 8765372543*y = 1

> ans 784426129 -485011369
CORRECT! Your flag is mini{B2_4a39f17045a8063e6eb0afa2}

LEVEL 3: give the integers x and y that satisfy a*x + b*y = c with smallest
         possible |x| + |y|:

  a = 172329615174258484389026493995284470243013873606078558711314460397670851456942410234121713652719725046736930219457185697597838781645377593188376635674458514137402988415274695055808334695839436438924034168872425182706138637584824074845746669005801723938330993778108851070552409088962751784310957757082836431093300116826362
  b = 28356761906716612873881138710402902897347022365354411652739208693325513167251446458912103549741332079105794174802290037963900303459422464736407225394752372764336652283336292253338385760630286153548854753862316744878470244746596115894407579090226051336510357308468389580782413423780615862345700844128007232811673170490170
  c = 13657769199596610482

> ans -716740480992306813107503753418846234036640156759836661475354416766574545237010296962263824224509107612115141091065808866650335667339422168844609337650456083904714828583142795906730708621014510898197333708554115609551003952289103814240209709219851287729419355090392174924377596434397802758684489757519 4355772766846172289550960484253309708628309981859354451608388213582133495086922647575976048691479746491014530235602502674014803098803037825125357480987981590580196394415483266364546368978087653972266116991312510608494888084750532763692967382260459363590590286778039861513365053641201896497684198556508
CORRECT! Your flag is mini{B3_c2ab64728ae65e273b7987ee}

COMPLETED all levels in this area.
```
I used sympy to solve the diophantine equations.<br>
Going west again gets us to location I.

## I
```
> w
You went west.

As you journey on, the weather suddenly turns and you realize that a storm is 
imminent. Luckily you spot a big oak tree and manage to find shelter under its
canopy just in time. While the hail falls, you have time to contemplate the 
lectures by your old mentors. Perhaps the answers won't elude you this time?

LEVEL 1: factor the number 48263. (E.g., for 12, you would answer 2 2 3)

> ans 17 17 167
CORRECT! Your flag is mini{I1_1a8ec6471c8824fff864a95c}

LEVEL 2: factor the number 8477969543906630921459041527576694. (E.g., for 12, you would answer 2 2 3)

> ans 2 7 7 13 19 19 79 601 234490397 1655726489421517
CORRECT! Your flag is mini{I2_03ba7452553b74b5122c58f0}

LEVEL 3: factor the number 71142975216676910225445498956472658317166395374468624230332488059276850400024521063814543607909086075571109949

> ans 3 11 31 29515817 1075612307646757041328543 1810939816479001125535889581 1209600061687323613153983466766686569317548327433
CORRECT! Your flag is mini{I3_8bfabf5fabe9ddeec6ebce31}

COMPLETED all levels in this area.
```
Find prime factors.
For the first two I used sympy.factorint.
For the third I got the first 4 factors with factordb and then factored the remaining number with Alpertron.
Then I put those factors into factordb and got the answer.

West again gets us to location K

## K
```
> w
You went west.

The road curves and gives way to marshland. You tread by one careful
step after another, focused so much on your footings that you only notice the
lizardman when he starts talking to you. "Hello, I am in the Enformation
Commerce. We two must have things to trade." He needs help with math to break
some encrypted messages.

LEVEL 1: solve the equations below for x and y

         (76*x + 221*y) mod 281 = 85
         (171*x + 190*y) mod 281 = 138

> ans 111 275
CORRECT! Your flag is mini{K1_cc1c3c9a5695228061017a76}

LEVEL 2: solve the equations below for x and y

         (8537681*x + 2471394*y) mod 8715383 = 1901941
         (4650550*x + 6247615*y) mod 8715383 = 1098848

> ans 5415645 1561936
CORRECT! Your flag is mini{K2_909bab4915b35706dfa54f05}

LEVEL 3: find x, y, and N, if we know that N is a prime and 

           (A*x + B*y) mod N = C
           (D*x + E*y) mod N = F
           (G*x + H*y) mod N = I

  A = 21831285386116329336808413851154012866
  B = 134179293514007351709197019177330444915
  C = 330381653200657403372617268197336743779
  D = 122250463455825590287911447642817402561
  E = 380808038683121265859993106659221016535
  F = 167613919641031436550368729835629765957
  G = 348695986646393565943251192097904044414
  H = 154755784779510244395471253499438548399
  I = 19514348735351843258338241386050978799
```
THIS IS INCOMPLETE.
The first two were solved with sympy using the method described at https://stackoverflow.com/questions/62599169/solving-systems-of-equations-modulo-a-certain-number-with-or-without-numpy

We can no longer go west, so going south gets us to location D.

## D
```
> s
You went south.

As dusk falls you make camp at a logging area. There are tree stumps
everywhere, some truly gigantic ones too. You are just about to fall asleep
when you hear footsteps - one of the fellers came back for his axe. He moves
sluggishly as if his limbs were made of lead, totally obliviously to your
presence. As he leaves you catch him grumbling about how hard this line of 
work is. Your eyes close and you dream, of something quite peculiar...

LEVEL 1: find an integer that satisfies 11^x mod 101 = 27
         (here ^ means exponentiation, e.g., 2^7 mod 5 = 3)

> ans 39
CORRECT! Your flag is mini{D1_77858210bb3c8f6f90642947}

LEVEL 2: find an integer that solves 29^x mod 2582957213 = 2170396238

> ans 1768477821
CORRECT! Your flag is mini{D2_1ef1a7b34c258a52260f06bf}

LEVEL 3: give the smallest positive integer that solves 137^x mod a = b, where

  a = 8711397949111576691212959376786755312511985069545395246877440965077478774468934756001391309042286116978264258298558869771314939991001082398339822258440522123
  b = 3351664603444796351468067743627025603502901539830658952546789142275777455261591099982137670634903607997743639964603135521965024437504489798875078878193244768
```
INCOMPLETE<br>
First two solved with sympy discrete_log
We can only go north or south. To the south is location C.

## C
```
> s
You went south.

Higher up on the hillside you come across a small house with a tidy garden.
An elderly rabbit lady in a rocking chair is observing you, while she nibbles
on some sort of brown root (carrot maybe?). "Have some, my dear" she says,
"great for vision." You oblige, and indeed, as if finer distinctions started
to materialize in things. "Now we just need to calibrate the dose," says the
rabbit and gives you something colorful to peer into.

LEVEL 1: find an integer that satisfies x^2 mod 97 = 88

> ans 31
CORRECT! Your flag is mini{C1_4c88b7b4c11a9ee43f33e130}

LEVEL 2: find an integer that satisfies x^2 mod 1359203501 = 95422207

> ans 548653309
CORRECT! Your flag is mini{C2_2ce7b90aa9335b0cb0a3db6d}

LEVEL 3: give the smallest positive x for which x^12 mod p = a, where

         a = 1817525449797280602402956873386237720889680621662448878394577537780771524786955876245638699592180826704996032326091618875207339103593277472500067216389870
         p = 12779849905941677959186610420316494198424452561778642658582451521063175469853171114961122342052464710078864014592127176275630898014968982060325361045608439
```
INCOMPLETE<br>
Used sympy.nthroot_mod<br>
South to location A.

## A
```
> s
You went south.

You see an inn and decide that you deserve to splurge some on a good meal and
a comfy bed. The room is tidy and clean but you do notice certain little
visitors... mice. Fear not, the innkeeper's cat comes eagerly to your rescue.
But whenever it tries to catch one, the mouse quickly disappears in one of
many mouseholes in the room. With this game going on and on for minutes, you
swear those mice must be playing with the cat. Interesting, you think, there
must be a smarter way to capture small creatures...

LEVEL 1: find *small* nonzero integers x, y, z that satisfy 299*x + 355*y + 251*z = 0
         (e.g., x = 355*251, y = 299*251, z = -2*299*355 does not count)

> ans -13 6 7
CORRECT! Your flag is mini{A1_27f3abda81e75486b9299fda}

LEVEL 2: find small nonzero integers x, y, z that satisfy a*x + b*y + c*z = 0,
         where a=69925405969, b=48507179354, c=32417688895

> ans 272371 -336786 -83569
CORRECT! Your flag is mini{A2_6bb458859e4518dc1e131618}

LEVEL 3: find nonzero integers v, w, x, y, z with a minimal sum of squares
         that satisfy a*v + b*w + c*x + d*y + e*z = 0, where

  a= 13224482656452729965010130774472519546513322282685222044383028560173414320699907502364037066998078684364749338920872578811245752029508639952579415409556998
  b= 11883954373554361547375474750630839024678353968736077156027924497730635501467831406890604708209797932039373450099216323200104673509462816247739552390501700
  c= 12033890847356726156410304461564041151269011907532227202193795241332802954932830212451456439198182308280974025227196605722871001660179705508977260220793964
  d= 2844873315637923430702813720068362602065731767047450571384220379074997608589211929239202046737041926913187483721774104817975966051912270671035046621837635
  e= 2606527713655043968153387630347865477764170887107821220448557599575906298221841101758877277715742039004267346644911989983884822836245158485633146455362314
```
INCOMPLETE<br>
Wrote a C++ program that checked all x for first 2.<br>
South no longer available, so going east gets us this message:
```
> e
You went east.

To the north is a narrow bridge that leads to the tower of the Greatest Crypto
Wizard of the land. Or, what remained of the bridge... Crossing the chasm 
below is surely impossible. A sign by the bridge says "You shall *not* pass."
```

Going east again gest us to location J.

## J
```
> e
You went east.

You make camp by a delapidated building that must have been a shrine in its
better days. As the rays of the setting sun illuminate the walls, you notice a
crevice with a piece of parchment tucked inside... a treasure map! Though you
cannot quite make out which direction is east or west, and north or south, on
the map, this *could* be payday - provided you figure out the right number of
steps to take.

LEVEL 1: find positive integers x, y that solve x^2 + 22*y^2 = 8383

> ans 21 19
CORRECT! Your flag is mini{J1_c9d7861b2635ebb151b71351}

LEVEL 2: find positive integers x, y that solve x^2 + 608268054*y^2 = 288964812689493391976023993

> ans 729485423 689247146
CORRECT! Your flag is mini{J2_ab5c40aa74a7c6ad5db7b041}

LEVEL 3: find positive integers x, y that solve x^2 + a*y^2 = b, where

  a = 809575361919189873249985593557526797315607233589
  b = 453911665595804740746927043910783828583622477123414312540919542168796850447209357992143785144169862380534061054229556425568794584043785497763918
```
INCOMPLETE<br>
Used sympy diop_quadratic<br>
Going east gets us to location E.

## E
```
> e
You went east.

A huge basin opens up to your view, wide swathes of farmland surrounded by a
ring of mountains in the distance. In the cool breeze your thoughts roam free
and wild... what if those mountains are really teeth, devouring a giant wafer
(the fields), and you are just an ant experiencing it all up close? You savor
each possibility conjured up by your mind - one can never know when some of
it comes handy.

LEVEL 1: consider polynomials in x with coefficients that are either 0 or 1.
         Suppose we multiply two such polynomials the usual way, except that
         in the result we substitute 0 for even coefficients, 1 for odd ones
         (this just means that coefficients live in the Galois field GF(2)).
         For example, (1+x)*(1+x) = 1+2*x+x^2 = 1+x^2.
            We can also map such polynomials to integers by simply taking the
         coefficients as a bit string. E.g., 1+x+x^4 = 1+x+0*x^2+0*x^3+x^4
         = 11001 in binary, which is 19 in decimal. Give the integer that is
         the result of the multiplication 35*23 in this setup.

> ans 729
CORRECT! Your flag is mini{E1_7bd94c75dbae3741d18a91ec}

LEVEL 2: consider the construction introduced in Level 1. Compute the
         remainder when 250062733632176 is divided by 406399853.
         I.e., convert the integers to polynomials, do the division,
         and convert the result back to an integer.
         (You can RESET the problem if you forgot what was in Level 1)

> ans 772769
Incorrect
> ans 90071293
CORRECT! Your flag is mini{E2_053d8dee20f001153f05afcc}

LEVEL 3: consider the construction introduced in Level 1 that mapped
         polynomials to integers. Find the solution to the equation
         a*y^2 + b*y + c = 0 in that setup, where

  a = 62988136202118127274037485756847228824659813916854388288704528975265641038375
  b = 61970982425686765788241036465223359125124685363948286523458864616239704859380
  c = 16032512672834824306563461964216557396271213056568232093692714812022221106419800157218922185040829131491280726002257183375575408421728567246659014589764356633340492085105583082470307172750166547566757359700457224812429817166783751
```
INCOMPLETE<br>
Wrote a `poly_to_num` and a `num_to_poly`, then used sympy Poly<br>
Going north gets us to location H.

## H
```
> n
You went north.

You are at a signpost, trying to figure out which path will get you through
the forest. While you are contemplating, another traveller arrives. The fellow
seems to know his way, so you decide to ask him. He gestures about (as if
asking a question?) but you hear nothing. It is then that you realize that he
cannot speak. You seem crestfallen but the traveller's face brightens - he
takes out parchment and ink from his bag and begins to write... something
that looks gibberish to you. Still, you do notice some familiarity in those
symbols...

LEVEL 1: the base64-encoded string below corresponds to XOR-encrypted
         text, with key length of 1 byte. What is the integer in the
         message?

PQEMSRoMChsMHUkABx0MDgwbSQAaSR0eDAcdEEQPAB8MSR0BBhwaCAcNRUkPAB8MSQEcBw0bDA1JCAcNSR0eDAUfDEc=

> ans 25512
CORRECT! Your flag is mini{H1_5ed3aca835bc208203da988b}

LEVEL 2: the base64-encoded string below corresponds to XOR-encrypted
         text, with key length of 4 bytes. What is the integer in the
         message?

BfEIGiL6CAE+900cavdJAC6zCBkvv0wLJPBdACn6CBkj60BOOPZPBj76Rxs5v0EALvZPACvrQQEk
v0kALr9MBznzQQUvv0ULJL9fBiW/SRwvv1sBav1NCT/2RAsuv0kALr9MCyfwWg8m9lILLr9KF2rr
QAtq/EAPOPJbTiX5CB4m+kkdP+1NTiX5CBoi+ggDJfJNAD6zCB0lv0oCI/FMCy6/Shdq+00dI+1N
QmrrQA8+v1wGL+YIDSvxRgE+v04BOPpbCy+/XAYvv1gPI/EIDyT7CBo48F0MJvoIGiL+XE4r7U1O
KPBdAC6/XAFq+kYdP/oTTivxTE4v7ghOHvdNTiPxXAst+lpOM/BdTj3+Rhpq9ltOe6wIGiW/XAYv
vxlfPvcIHiXoTRxk

> ans 1792160394037
CORRECT! Your flag is mini{H2_87a986c2cb527d326d204f52}

LEVEL 3: the base64-encoded file served at http://[THIS_HOST]/chal10
         corresponds to XOR-encrypted text, with unknown key length.
         What is the *key*, represented as a little-endian integer?
```
INCOMPLETE<br>
Frequency analysis over periods<br>
Going north gets us to location G.

## G
```
> n
You went north.

You stop by at a small village to quench your thirst. In its pub you find a
group of peasants, who are in the middle of a heated argument. As you sip your 
drink, you cannot help listening... is it about.. numbers?? One of them
points at you and asks, "Traveler, which of us is right? Ol' Jeff says he has
a clever way to make numbers small but we think that's just bollocks."

LEVEL 1: find a number that gives a remainder of 2 when divided by 5,
         a remainder of 6 when divided by 7, and a remainder of 9 when
         divided by 13

> ans 412
CORRECT! Your flag is mini{G1_92e9a33c80ca7666c7f4b704}

LEVEL 2: find a number that gives a remainder of 616 when divided by 1277,
         a remainder of 1892 when divided by 3911, and a remainder of 3267
         when divided by 6833

> ans 6429412122
CORRECT! Your flag is mini{G2_9aa73c3f86221f07d9b789a9}

LEVEL 3: give the smallest positive x that satisfies x mod a_i = b_i, where

  a1 = 5485948154512337139220437723513046430670172804
  a2 = 2108813835706513804248871264701897235977426762
  a3 = 59351473308659155928757459746804856485
  a4 = 924847477382640006890848669912858050701990
  a5 = 12741718618862212680555500636008445150492416265

  b1 = 2661929484162718513247006741545910067104673680
  b2 = 1051667267149052195100488400753935294543177150
  b3 = 47216332074545827727316304129354717936
  b4 = 532886655965436047074701814450039258213526
  b5 = 11163090230050187304714123613300073905576382766

> ans 1202114787574073135698562247558599073285047132156573830145908717087719050384755928081340071169158043961005726049447510357364537073462416777364540618918830057496883942982657669805211370184463326656
CORRECT! Your flag is mini{G3_a08d51fdb86b4ac7309e3f51}

COMPLETED all levels in this area.
```
Chinese Remainder Theorem using sympy.crt.<br>
Going west gets us to location F.

## F
```
> w
You went west.

As you trek through dense forest, you notice a giant snake curled up in the
center of a clearing ahead. You freeze, and try to tip-toe back, but it's too
late. "Count your blessssingsss, human, for I'm not hungry... thisss time.
Sssspeaking of counting... I can tell you sssecrets if you demonssstrate you
are capable.

LEVEL 1: how many primes are there between 1200 and 1500?

> ans 43
CORRECT! Your flag is mini{F1_c45a3e68b37e85ee427389c5}

LEVEL 2: how many primes are there between 123456780 and 234567890?
```
SKIPPED due to lack of time.<br>
