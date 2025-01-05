
**Title**: What Lies Within

**Description**:
There's something in the [building](https://jupiter.challenges.picoctf.org/static/011955b303f293d60c8116e6a4c5c84f/buildings.png). Can you retrieve the flag?


**Steps Taken**:
The hint suggested something might be hidden in the image.
This is where I learnt `Steganography`, the practise of encoding text within an image.

At first I tried to use the `steghide` command to extract the text, but it asked for a password which I dont have.
```
$ steghide extract -sf buildings.png 
Enter passphrase: 
```

Then I went online, since it says so in the hint too.
I come across this site: https://stylesuxx.github.io/steganography/

Click on decode and upload the image:
![[Pasted image 20241227142730.png]]


**Flag**: `picoCTF{h1d1ng_1n_th3_b1t5}`

**Learnings**:

### Steganography

It is the practice of encoding data into non-obvious files like images, links, videos, etc such that no one can determine what secret is hidden in the command.

This is done by altering and adding desired snippet/message in the pixels without significantly altering the image.

