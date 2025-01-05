
**Title**: Bases

**Description**:
What does this `bDNhcm5fdGgzX3IwcDM1` mean? I think it has something to do with bases.

**Steps Taken**:
This looks like a base64 text, let validate it.
Go to [base64validator-tool](https://base64.guru/tools/validator) and enter the text > click validate Base64.
![[Pasted image 20241222130831.png]]

So, let's go ahead and echo this text into a file as such:
```
$ echo "bDNhcm5fdGgzX3IwcDM1" >> Bases
```

Once created, let's use the `base64` tool to decode the text.
```
$ base64 -d Bases
l3arn_th3_r0p35
```
And, there it is!

**Flag**: `picoCTF{l3arn_th3_r0p35}`

**Learnings**:
### **Key Features of Base64:**

1. **Character Set**  
    Base64 uses a specific set of characters:
    
    - Uppercase letters: `A-Z`
    - Lowercase letters: `a-z`
    - Numbers: `0-9`
    - Special characters: `+` and `/`
    - Padding character: `=`
    
2. **Length is a Multiple of 4**
    - Base64 strings are always padded so their length is divisible by 4.
    - If the length isn't divisible by 4, padding with one or two `=` characters is added.
    
3. **Readable but Non-Human-Meaningful Text**
    - The encoded string looks like text but doesn't make sense when read directly (e.g., `SGVsbG8gd29ybGQh` decodes to "Hello world!").

4. **No Spaces or Special Characters**
    - Base64 strings are continuous and lack spaces, except in encoded files where line breaks might be added for formatting.