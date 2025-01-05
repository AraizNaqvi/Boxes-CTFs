
**Title**: 13

**Description**:
Cryptography can be easy, do you know what ROT13 is? `cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}`


**Steps Taken**:
As soon as you read ROT13 encyrption, just shut your eyes and go to [cyberchef-ROT13](https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13)&input=Y3ZwYlBHU3thYmdfZ2JiX29ucV9ic19uX2NlYm95cnp9), once you're there just enter the strange text you see in the description there.


**Flag**: `picoCTF{not_too_bad_of_a_problem}`

**Learnings**:
ROT13 is a cipher where each alphabet replaces its next 13th counterpart.
A becomes N, B becomes O and so on. 
The speciality of this cipher is that it encodes and decodes the same way cause there are 26 letters in the alphabet and 13 is half of that. So, simply decode it using ROT13 itself.