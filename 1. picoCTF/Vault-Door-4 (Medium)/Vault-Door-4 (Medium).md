
**Title**: Vault-Door-4

**Description**:
This vault uses ASCII encoding for the password. The source code for this vault is here: [VaultDoor4.java](https://jupiter.challenges.picoctf.org/static/834acd392e0964a41f05790655a994b9/VaultDoor4.java)


**Steps Taken**:
In the beginning, upon looking through the java code:
```
$ cat VaultDoor4.java 
import java.util.*;

class VaultDoor4 {
    public static void main(String args[]) {
        VaultDoor4 vaultDoor = new VaultDoor4();
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

    // I made myself dizzy converting all of these numbers into different bases,
    // so I just *know* that this vault will be impenetrable. This will make Dr.
    // Evil like me better than all of the other minions--especially Minion
    // #5620--I just know it!
    //
    //  .:::.   .:::.
    // :::::::.:::::::
    // :::::::::::::::
    // ':::::::::::::'
    //   ':::::::::'
    //     ':::::'
    //       ':'
    // -Minion #7781
    public boolean checkPassword(String password) {
        byte[] passBytes = password.getBytes();
        byte[] myBytes = {
            106 , 85  , 53  , 116 , 95  , 52  , 95  , 98  ,
            0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
            0142, 0131, 0164, 063 , 0163, 0137, 0146, 064 ,
            'a' , '8' , 'c' , 'd' , '8' , 'f' , '7' , 'e' ,
        };

	passBytes = myBytes;
        for (int i=0; i<32; i++) {
		System.out.println((char)myBytes[i]);
        }
        return true;
    }
}

```

You scroll to the bottom and have a look at this part:
![[Pasted image 20241230160139.png]]

So, I decided that since I can hinder with the code itself, why not just print the respective characters directly. So the updated `checkpassword()` is:
```
public boolean checkPassword(String password) {
        byte[] passBytes = password.getBytes();
        byte[] myBytes = {
            106 , 85  , 53  , 116 , 95  , 52  , 95  , 98  ,
            0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
            0142, 0131, 0164, 063 , 0163, 0137, 0146, 064 ,
            'a' , '8' , 'c' , 'd' , '8' , 'f' , '7' , 'e' ,
        };

        passBytes = myBytes;
        for (int i=0; i<32; i++) {
                System.out.println((char)myBytes[i]);
        }
        return true;
    }
```

Now, when you run the code as:
```
$ javac VaultDoor4.java
```

```
$ ls
VaultDoor4.class  VaultDoor4.java
```

```
$ java VaultDoor4
Enter vault password: picoCTF{hehe}
j
U
5
t
_
4
_
b
U
n
C
h
_
0
f
_
b
Y
t
3
s
_
f
4
a
8
c
d
8
f
7
e
Access granted.

```

Note: Your password should begin with `picoCTF{` as that's how it is used in the `main()`.

**Flag**: `picoCTF{ju5t_4_bunch_0f_bYt3s_f4a8cd8f7e}`

**Learnings**:
A hacker uses the source code to grant himself access such that the code works for them.
(A little philosophical but yes!)