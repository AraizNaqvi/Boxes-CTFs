
**Title**: logon

**Description**:
The factory is hiding things from all of its users. Can you login as Joe and find what they've been looking at? `https://jupiter.challenges.picoctf.org/problem/15796/` ([link](https://jupiter.challenges.picoctf.org/problem/15796/)) or http://jupiter.challenges.picoctf.org:15796


**Steps Taken**:
Let's go to the website.
Now, looking at the source code there's nothing much that special. But, let's mess with the cookies.

First, just type the following and wait:

![[Pasted image 20241222135421.png]]

Then, open the inspect using `ctrl+shift+i` and go to `applications` > `cookies`:
![[Pasted image 20241222152948.png]]

Once here, now hit the `sign up` and you'll see an admin cookie show up with value `False`.
![[Pasted image 20241222153100.png]]

Set this `False > True`.
Then refresh and you shall have the flag.




**Flag**: `picoCTF{th3_c0nsp1r4cy_l1v3s_6edb3f5f}`

**Learnings**:
This is a **Cookie Tampering** or more famously a mini **IDOR** or **Insecure Direct Object Reference** attack.
Cookies are used to store user session data, and if the session cookies are changed you might as well just get in.