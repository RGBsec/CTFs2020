# NACTF 2020 Writeups: Dr. J's Vegetable Factory #1, #2, and #3
I was unable to solve #4 and #5.

## \#1
Points: 50
> After years of collecting plush vegetable toys, Dr. J decided to take on his true passion: starting a vegetable factory. Dr. J is incredibly organized, so he likes all of his vegetables to be in the proper order. In fact, he built a robot "Turnipinator-1000" to alphabetize his vegetables for him! Unfortunately, Dr. J doesn't know what instructions to give Turnipinator-1000. Can you help him out? 🥬🥕🌽🍆🥦🥒🥑🍄<br><br>
> `nc challenges.ctfd.io 30267`<br><br>
> Give instructions in the form of numbers separated by spaces. Entering the number x will swap the vegetable in position x with the vegetable in position x+1. Positions start at zero, not one. (Dr. J is a programmer after all.) For example, given the following vegetables: Avocado, Brocolli, Eggplant, Daikon Radish, Carrot, one possible solution is "3 2 3"<br>
> Avocado, Brocolli, Eggplant, Daikon Radish, Carrot<br>
> (swap 3 and 4)<br>
> Avocado, Brocolli, Eggplant, Carrot, Daikon Radish<br>
> (swap 2 and 3)<br>
> Avocado, Brocolli, Carrot, Eggplant, Daikon Radish<br>
> (swap 3 and 4)<br>
> Avocado, Brocolli, Carrot, Daikon Radish, Eggplant<br>
> The20thDuck

Hint:
> Try sorting the vegetables by hand! For example: [insertion sort](https://www.geeksforgeeks.org/insertion-sort/).

We can do a merge-sort based algorithm. See `solve1` in `solve_vegetable_factory.py`.<bR>
Flag: `nactf{1f_th3r3s_4_pr0b13m_13ttuce_kn0w_db4d736fd28f0ea39ec}`


##\#2
Points: 150
> Dr. J expanded his vegetable factory! Now he's got hundreds of vegetables. Same problem as last time: can you give Turnipinator-1000 the right instructions to sort Dr. J's vegetables? 🥬🥕🌽🍆🥦🥒🥑🍄<br><br>
> `nc challenges.ctfd.io 30267`<br><br>
> The20thDuck

Hint:
> It seems like there are too many vegetables to sort by hand this time. But not too many for a computer!<br><br>
> Check out the example script if you're unsure of how to connect to the server with code! [example.py](https://www.nactf.com/files/0f845c53ada888bb510e15b286a7acea/example.py)

We can use the same program: `nactf{d0n7_w0rry_p34_h4ppy_f27ae283dd72cb62f685}`


##\3
Points: 175
> Rahul hates vegetables. Rahul hates vegetables so much that he snuck into Dr. J's factory at night to sabotage Dr. J's vegetable production! He brought a sledgehammer and broke the wheels of Dr. J's robot! 😓 Now the robot is stuck in place, and instead of being able to swap any adjacent elements, it can only swap the elements in positions 0 and 1!
> But Dr. J won't let this incident stop him from giving the people the vegetables they deserve! Dr. J is a problem solver 🧠. He organized his vegetables in a circle, and added a conveyor-belt that allows him shift the positions of the vegetables. He thinks that the conveyor belt should make it possible to sort his vegetables, but he's not 100% sure. Can you help him out?<br><br>
> `nc challenges.ctfd.io 30267`<br><br>
> Enter letters separated by spaces to sort Dr. J's vegetables. Entering "c" will activate the conveyor belt and shift all vegetables left one position. Entering "s" will swap the vegetable in position 0 with the vegetable in position 1.<br>
> The20thDuck

I wrote another program: `nactf{1t_t4k35_tw0_t0_m4n90_8a51c7b47fbe227}`<br>
This time we can continuously rotate and swap if the items at indexes 0 and 1 are out of order.
Since we might compare the first and last we need to make sure that the first element never gets swapped.