
**Title**: Shark On Wire 2

**Description**:
We found this [packet capture](https://jupiter.challenges.picoctf.org/static/b506393b6f9d53b94011df000c534759/capture.pcap). Recover the flag that was pilfered from the network.


**Steps Taken**:
Oh, boy! This was a tough one for me!

But, first as normal, go through the `capture.pcap`.
At first, nothing seems to make sense so I try to see `udp` packets since data within them can be easily read.

So, I apply filter:
```
udp
```
![[Pasted image 20241225131634.png]]

Next, let's also take into the filter, destination port of 22.
Done as:
```
udp && udp.dstport==22
```
![[Pasted image 20241225132001.png]]

Look at this for reference: http://sticksandstones.kstrom.com/appen.html

Now, I'm going to want to capture data in the form of the last three digits from the source port. For this I will use `tshark`.

First, use the following command to select the file and set the same filter that we did on wireshark as:
```
$ tshark -r capture.pcap -Y "udp && udp.dstport==22"
```
![[Pasted image 20241225132305.png]]

Let's use the awk command the print the `$2` i.e. is the second piece of text where all are separated by spaces which will select for example 5000 and then `substr` it to get everything after the 5 i.e. 000.
Done as:
```
$ tshark -r capture.pcap -Y "udp && udp.dstport==22" | awk '{print substr($2, 2)}'
```
![[Pasted image 20241225132505.png]]

Now, let's save this in a `tshark-filtered-data.txt` using the `>` command as:
```
tshark -r capture.pcap -Y "udp && udp.dstport==22" | awk '{print substr($2, 2)}' > tshark-filtered-data.txt
```

Now, we're ready to write a `bash` file. So, lets create a bash file called `extract-ascii.sh` and give it execute permissions:
```
$ touch extract-ascii.sh; chmod 744 extract-ascii.sh
```

Let's use the good old `vim` to create the bash as:
```
#!/bin/bash

# please note that any comment is explaining the command above it

while read -r line; do
        line=$(echo "$line" | sed 's/^0//')
        # Searches for any first 0's and removes them since when we convert the decimal
        # say 060 to hexa, it will get rejected due to the leading 0.
        # So, if 060 passes => 60. But if 112 passes => 112
        # cause it is only removing 1 zero at the beginning if any

        charac=$(printf "\\$(printf '%03o' $line)")
        echo "Character: $charac"
        # The above 2 lines convert the formatted string to hexa and directly
        # print it which gives us the actual character which is stored in the
        # 'charac' variable which when passed to echo prints it.

done < tshark-filtered-data.txt
# The '<' inputs the .txt where we stored the numbers to the who loop you just wrapped your head around.



# Written by Araiz Naqvi

```

Now, just read the output by running the file and the flag is yours to keep ;)
```
$ bash extract-ascii.sh
```

**Flag**: `picoCTF{P1LLf3r3d_data_v1a_st3g0}`

**Learnings**:
#### Creating a script

To create a script, simply run `touch <name-of-script>`
To recognise script as bash we need to add a shebang, which was `!/bin/bash` at the very beginning.
To execute it, simply run `bash <name-of-script>.sh`

#### `sed`

`sed` is a command line utility for text processing.
When I did `sed 's/^0*//'`:
- `^` ~ Asserts start of the line
- `0*` ~ Matches zero or more occurences of strings starting with 0
- `//` ~ is the replacement part, wherein if the '0' is removed then it is replaced by nothing

