# My solutions for the cryptopals crypto challenges

I'm trying to solve all of these challenges, so I figured I may as well put everything in git like some kind of real developer.

Everything has been written in Python 3.

## Layout/Scheme

There are several directories in this repository named `set#`, which correspond to the sets in the challenge. Each of those directories contains several files named `challenge##.py` to indicate which challenge they are the solution for.

Every time I write a new function, I will include it in the solution file for the challenge for which I wrote it. After that, if it is reused, it will simply be imported from a copy stored in `common.py` at the top level.
