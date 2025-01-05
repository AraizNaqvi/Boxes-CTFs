
**Title**: vault-door-5

**Description**:
In the last challenge, you mastered octal (base 8), decimal (base 10), and hexadecimal (base 16) numbers, but this vault door uses a different change of base as well as URL encoding! The source code for this vault is here: [VaultDoor5.java](https://jupiter.challenges.picoctf.org/static/0a53bf0deaba6919f98d8550c35aa253/VaultDoor5.java)


**Steps Taken**:
The very first step is obviously reading the java file.
Upon opening first I read the entire codes meaning:

```
import java.net.URLDecoder;
import java.util.*;

class VaultDoor5 {
    public static void main(String args[]) {
        VaultDoor5 vaultDoor = new VaultDoor5();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
	String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
	if (vaultDoor.checkPassword(input)) {
	    System.out.println("Access granted.");
	} else {
	    System.out.println("Access denied!");
        }
    }

    // Minion #7781 used base 8 and base 16, but this is base 64, which is
    // like... eight times stronger, right? Riiigghtt? Well that's what my twin
    // brother Minion #2415 says, anyway.
    //
    // -Minion #2414
    public String base64Encode(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    // URL encoding is meant for web pages, so any double agent spies who steal
    // our source code will think this is a web site or something, defintely not
    // vault door! Oh wait, should I have not said that in a source code
    // comment?
    //
    // -Minion #2415
    public String urlEncode(byte[] input) {
        StringBuffer buf = new StringBuffer();
        for (int i=0; i<input.length; i++) {
            buf.append(String.format("%%%2x", input[i]));
        }
        return buf.toString();
    }

    public boolean checkPassword(String password) {
        String urlEncoded = urlEncode(password.getBytes());
        String base64Encoded = base64Encode(urlEncoded.getBytes());
        String expected = "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm"
                        + "JTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2"
                        + "JTM0JTVmJTMwJTYyJTM5JTM1JTM3JTYzJTM0JTY2";
        return base64Encoded.equals(expected);
    }
}

```

Let's break it down in the order it works in:
![[Pasted image 20241227130044.png]]

![[Pasted image 20241227130243.png]]

All this garbage is `base64`
I tried to manually copy and decode the base64 to hexa as below and got some amazing output:
```
$ echo "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm" | base64 -d
%63%30%6e%76%33%72%74%31%6e%67%5f
```

This hexa just by formatting and removing the `%` signs can be converted to plain text.
Also, as soon as converted to the formatted hexa we need them as, let's also decode it using `xxd` command:
```
$ echo "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm" | base64 -d | sed 's/%//g' | xxd -r -p
c0nv3rt1ng_
```
(Don't worry, i've explained all these commands in detail in the Learnings section)

Similarly, let's do the same for the other strings too.
And we get `c0nv3rt1ng_fr0m_ba5e_64_0b957c4f` now simply suffix a `}` to it.


**Flag**: `picoCTF{c0nv3rt1ng_fr0m_ba5e_64_0b957c4f}`

**Learnings**:
The `|` or pipes take output of command on left and pass to command on right.
So echoing the string and piping it to the `base64 -d` will print the string and pass it to base64 that will work on it next.

Now, `sed` is Stream Editor and helps to modify strings right in the terminal.
`sed /s/%//g`:
- `/s` ~ Represents substitution
- `/%` ~ Represents what we want to substitute
- `/` ~ Represents nothing, so nothing is replaced.
- `/g` ~ Represents everywher you find `%`, remove it but dont put anything there.

Finally, `xxd` simply allows us to decode hexa code. Simple :)