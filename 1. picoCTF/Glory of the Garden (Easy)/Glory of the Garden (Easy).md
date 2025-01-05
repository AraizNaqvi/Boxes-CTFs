
**Title**: Glory of the Garden

**Description**:
This [garden](https://jupiter.challenges.picoctf.org/static/4153422e18d40363e7ffc7e15a108683/garden.jpg) contains more than it seems.


**Steps Taken**:
First, I really had no clue. Then I quite honestly had a look at the hint.

I installed `hexedit` and tried to `cat` command it to a file cause it was huge.
```
$ sudo apt install hexedit -y
$ hexedit garden.jpg > gardenhere.txt
```
And obviously, it was taking a lot of time!

So, then I decided to make a hexdump which should take relatively less time.
```
$ xxd garden.jpg > gardenhere.txt
```

Then when you `cat` the file, you get:
```
$ cat gardenhere.txt
```

Again a large amount of text, but at the bottom of it, you'll find what you're looking for!

![[Pasted image 20241222160931.png]]


**Flag**: `picoCTF{more_than_m33ts_the_3y33dd2eEF5}`

**Learnings**:
`Hexedit` is a hexadecimal editor that allows to view and edit the raw bytes of a file.
The left column is the raw bytes and the right is its corresponding ASCII.

