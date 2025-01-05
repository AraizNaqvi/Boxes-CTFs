
**Title**: dont-use-client-side

**Description**:
Can you break into this super secure portal? `https://jupiter.challenges.picoctf.org/problem/29835/` ([link](https://jupiter.challenges.picoctf.org/problem/29835/)) or http://jupiter.challenges.picoctf.org:29835


**Steps Taken**:
The page itself shows no breaks, but if you look at the source code, you'll see a password checker which checks for the exact words! That's our breaking point!

It looks like this:
```
split = 4;|
if (checkpass.substring(0, split) == 'pico') {|
if (checkpass.substring(split*6, split*7) == '723c') {|
if (checkpass.substring(split, split*2) == 'CTF{') {|
if (checkpass.substring(split*4, split*5) == 'ts_p') {|
if (checkpass.substring(split*3, split*4) == 'lien') {|
if (checkpass.substring(split*5, split*6) == 'lz_7') {|
if (checkpass.substring(split*2, split*3) == 'no_c') {|
if (checkpass.substring(split*7, split*8) == 'e}') {|
alert("Password Verified")|
```

The max length the password can be based on the `split` keywords is `4*8=32`.
So, let's create for simplicity a hangman.

```
_ _ _ _ _ _ _ _ _ _ _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _ 
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29

_  _ 
30 31
```

Now, from position 0 to 3 is `pico`, so:
```
p i c o _ _ _ _ _ _ _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _ 
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29

_  _ 
30 31
```

Now, from position 24 to 27 is `723c`, so:
```
p i c o _ _ _ _ _ _ _  _  _  _  _  _  _  _  _  _  _  _  _  _  7  2  3  c  _  _ 
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29

_  _ 
30 31
```

Now, from position 4 to 7 is `CTF{`, so:
```
p i c o C T F { _ _ _  _  _  _  _  _  _  _  _  _  _  _  _  _  7  2  3  c  _  _ 
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29

_  _ 
30 31
```

Now, from position 16 to 19 is `ts_p`, so:
```
p i c o C T F { _ _ _  _  _  _  _  _  t  s  _  p  _  _  _  _  7  2  3  c  _  _ 
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29

_  _ 
30 31
```

Now, from position 12 to 15 is `lien`, so:
```
p i c o C T F { _ _ _  _  l  i  e  n  t  s  _  p  _  _  _  _  7  2  3  c  _  _ 
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29

_  _ 
30 31
```

Now, from position 20 to 23 is `lz_7`, so:
```
p i c o C T F { _ _ _  _  l  i  e  n  t  s  _  p  l  z  _  7  7  2  3  c  _  _ 
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29

_  _ 
30 31
```

Now, from position 8 to 11 is `no_c`, so:
```
p i c o C T F { n o _  c  l  i  e  n  t  s  _  p  l  z  _  7  7  2  3  c  _  _ 
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29

_  _ 
30 31
```

Now, from position 28 to 31 is `e}`, so:
```
p i c o C T F { n o _  c  l  i  e  n  t  s  _  p  l  z  _  7  7  2  3  c  e  } 
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29

_  _ 
30 31
```

And, there's our flag! (Oh what an effort writing the above down XD)

**Flag**: `picoCTF{no_clients_plz_7723ce}`

**Learnings**:
Sometimes in case of a static password, the credential can be found via the source code.
There's sometimes a conditional checker for the password, from where it can easily found and if needed decoded.