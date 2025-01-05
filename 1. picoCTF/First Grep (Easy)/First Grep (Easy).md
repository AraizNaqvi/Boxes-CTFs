
**Title**: First Grep

**Description**:
Can you find the flag in [file](https://jupiter.challenges.picoctf.org/static/315d3325dc668ab7f1af9194f2de7e7a/file)? This would be really tedious to look through manually, something tells me there is a better way.


**Steps Taken**:

After downloading the file, I use the `cat` command to read through the contents of the file, and oh boy what a mistake, it was a mess:
*(Btw I tend to rename the downloaded files to the name of the pico challenge, so relate please)*
```
$ cat first-grep
```

![[Pasted image 20241222121933.png]]
And a lot more...

But, somewhere within this mess is the flag. And since all flags are prefixed with `pico`, let's `grep` for that.
```
$ cat first-grep | grep "pico"
```

![[Pasted image 20241222122120.png]]
And, voila! There it is!


**Flag**: `picoCTF{grep_is_good_to_find_things_f77e0797}`


**Learnings**:
The text we see is simply gibberish and to find a certain text in a whole bunch of text, `grep` comes in handy, since it can pin-point exactly what you're looking for.