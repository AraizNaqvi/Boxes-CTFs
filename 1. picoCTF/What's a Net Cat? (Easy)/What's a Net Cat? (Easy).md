
**Title**: What's a Net Cat?

**Description**:
Using netcat (nc) is going to be pretty important. Can you connect to `jupiter.challenges.picoctf.org` at port `64287` to get the flag?


**Steps Taken**:
It's literally obvious that you need to use `nc`.
The most basic syntax that goes in `nc` is of the format:
```
nc <host-name> <port>
```

So,
```
$ nc jupiter.challenges.picoctf.org 64287
You're on your way to becoming the net cat master
picoCTF{nEtCat_Mast3ry_284be8f7}
```


**Flag**: `picoCTF{nEtCat_Mast3ry_284be8f7}`

**Learnings**: