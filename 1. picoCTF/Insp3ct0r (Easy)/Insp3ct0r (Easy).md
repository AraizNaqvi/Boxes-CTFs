
**Title**: Insp3ct0r

**Description**:
Kishor Balan tipped us off that the following code may need inspection: `https://jupiter.challenges.picoctf.org/problem/9670/` ([link](https://jupiter.challenges.picoctf.org/problem/9670/)) or http://jupiter.challenges.picoctf.org:9670

**Steps Taken**:
As soon as you click on how part of the page, you see HTML, CSS and JS being used.
This hints at where to look cause it feels like emphasis was given on it.
![[Pasted image 20241223222032.png]]

Upon looking at the source code, firstly on the HTML side of things at the very bottom is a comment that gives part of the flag away. Also, look out for the CSS and JS links.
![[Pasted image 20241223222333.png]]

For part 2, let's check it out in the right sequence.
Let's check out the CSS, go to the link https://jupiter.challenges.picoctf.org/problem/9670/mycss.css to check the CSS:
![[Pasted image 20241223222513.png]]

For part 3, let's check out the JS now at https://jupiter.challenges.picoctf.org/problem/9670/myjs.js:
![[Pasted image 20241223222611.png]]
By combining the three flags, we get the full flag.

**Flag**: `picoCTF{tru3_d3t3ct1ve_0r_ju5t_lucky?2e7b23e3}`

**Learnings**: