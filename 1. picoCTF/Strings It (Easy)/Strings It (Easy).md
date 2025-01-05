
**Title**: Strings It

**Description**:
Can you find the flag in [file](https://jupiter.challenges.picoctf.org/static/94d00153b0057d37da225ee79a846c62/strings) without running it?


**Steps Taken**:
Simple! It's a string file.
So just use the `strings` command to read it.

Wait! Not yet, if you do:
```
$ strings strings
```
(where the 2nd strings is the file name)
you'll see a huge mess of data.

So, we'll use `grep`, done as:
```
$ strings strings | grep "pico"
```

And, we get the flag!


**Flag**: `picoCTF{5tRIng5_1T_d66c7bb7}`

**Learnings**:
The `cat` command does not work with strings.
Just use the `strings` command then.