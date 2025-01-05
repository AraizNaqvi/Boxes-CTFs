
**Title**: like1000

**Description**:
This [.tar file](https://jupiter.challenges.picoctf.org/static/52084b5ad360b25f9af83933114324e0/1000.tar) got tarred a lot.


**Steps Taken**:
Upon having first look at the `1000.tar` file, let's extract it once and see what we get:
```
$ tar -xf 1000.tar
```

The result will be a `999.tar`. So, clearly the result is decremented by 1.
Let's get on with the bash script:

```
#!/bin/bash

# Note: All comments explain the line above them!


iter=1000
# The 'iter' variable is what will iterate over the .tar since as we just saw
# that it goes from 1000.tar>999.tar>998.tar and so on...

while [ $iter -ne 0 ]; do
        tar -xf "$iter.tar"
        # This is the line where we extract the .tar file
        # You can also see that $iter.tar will resemble in first case 1000.tar
        # then 999.tar and so on.

        rm $iter.tar
        # Since we don't want our file system to be filled with tars, let's
        # also remove them simultaneously.
        # So, as soon as 1000.tar is extracted, it shall also be removed!

        iter=$(($iter-1))
        # This sets the variable name to the newly extracted variable
done

echo "Completed!"
# Just to signify that process has completed with no issues!

```


Once completed, you get a `flag.png`.
This `png` will contain the flag. Open it using:
```
xdg-open flag.png
```
![[Pasted image 20241225155002.png]]


**Flag**: `picoCTF{l0t5_0f_TAR5}`
