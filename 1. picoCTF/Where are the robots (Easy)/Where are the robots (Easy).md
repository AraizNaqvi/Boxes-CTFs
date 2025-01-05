
**Title**: Where are the robots

**Description**:
Can you find the robots? `https://jupiter.challenges.picoctf.org/problem/56830/` ([link](https://jupiter.challenges.picoctf.org/problem/56830/)) or http://jupiter.challenges.picoctf.org:56830

**Steps Taken**:
Let's start by heading over to the website.
The robots name gives it away. There might be a robot.txt page hiding disallowed URL's, so let's give it a shot!

Enter https://jupiter.challenges.picoctf.org/problem/56830/robots.txt in the box.
![[Pasted image 20241223224429.png]]

Let's log onto the website with this extension https://jupiter.challenges.picoctf.org/problem/56830/1bb4c.html . Now, we see:
![[Pasted image 20241223224524.png]]

And, voila! There it is!


**Flag**: `picoCTF{ca1cu1at1ng_Mach1n3s_1bb4c}`

**Learnings**:
`/robots.txt` is an extension which holds disallowed URL's or in other words is a text file used by the website to communicate with web crawlers and search engines, specifying which parts of the website they are allowed or disallowed to see.

Usually, it is suffixed as:
```
http://example.com/robots.txt
```

Output looks like this:
```
User-agent: *
Disallow: /private/
Disallow: /admin/
Allow: /public/
```
