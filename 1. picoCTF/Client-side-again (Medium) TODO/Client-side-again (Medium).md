
**Title**: Client-side-again

**Description**:
Can you break into this super secure portal? `https://jupiter.challenges.picoctf.org/problem/6353/` ([link](https://jupiter.challenges.picoctf.org/problem/6353/)) or http://jupiter.challenges.picoctf.org:6353


**Steps Taken**:
The very first step was to check the source code.
Hit `Ctrl+u` to check out the source code.
Out of all there's one part that strikes the most:
![[Pasted image 20241231200902.png]]

Let's copy this script and paste it to a JS [deobfuscator](https://deobfuscate.io/).
This in turn returns:
```
var _0x5a46 = ["0a029}", "_again_5", "this", "Password Verified", "Incorrect password", "getElementById", "value", "substring", "picoCTF{", "not_this"];
(function (_0x4bd822, _0x2bd6f7) {
  var _0xb4bdb3 = function (_0x1d68f6) {
    while (--_0x1d68f6) {
      _0x4bd822.push(_0x4bd822.shift());
    }
  };
  _0xb4bdb3(++_0x2bd6f7);
}(_0x5a46, 435));
var _0x4b5b = function (_0x2d8f05, _0x4b81bb) {
  _0x2d8f05 = _0x2d8f05 - 0;
  var _0x4d74cb = _0x5a46[_0x2d8f05];
  return _0x4d74cb;
};
function verify() {
  checkpass = document[_0x4b5b("0x0")]("pass")[_0x4b5b("0x1")];
  split = 4;
  if (checkpass[_0x4b5b("0x2")](0, split * 2) == _0x4b5b("0x3")) {
    if (checkpass[_0x4b5b("0x2")](7, 9) == "{n") {
      if (checkpass[_0x4b5b("0x2")](split * 2, split * 2 * 2) == _0x4b5b("0x4")) {
        if (checkpass[_0x4b5b("0x2")](3, 6) == "oCT") {
          if (checkpass[_0x4b5b("0x2")](split * 3 * 2, split * 4 * 2) == _0x4b5b("0x5")) {
            if (checkpass.substring(6, 11) == "F{not") {
              if (checkpass[_0x4b5b("0x2")](split * 2 * 2, split * 3 * 2) == _0x4b5b("0x6")) {
                if (checkpass[_0x4b5b("0x2")](12, 16) == _0x4b5b("0x7")) {
                  alert(_0x4b5b("0x8"));
                }
              }
            }
          }
        }
      }
    }
  } else {
    alert(_0x4b5b("0x9"));
  }
}

```


Looking at the functions and keywords involved this has to do with verifying the password.
But still not everyhting is clear, so let's break it down step by step.

The following function:
```
var _0x4b5b = function(_0x2d8f05, _0x4b81bb) {
    _0x2d8f05 = _0x2d8f05 - 0;
    var _0x4d74cb = _0x5a46[_0x2d8f05];
    return _0x4d74cb;
};
```
 
 upon noticing works as follows:
 It accepts parameters wherein `_0x2d8f05` = `_0x2d8f05 - 0` which means value remains the same. Now, variable `_0x4d74cb` equals `_0x5a46[_0x2d8f05]` which refers to some array and if you look deeply, in fact it is an array:
 ```
 var _0x5a46 = ["0a029}", "_again_5", "this", "Password Verified", "Incorrect password", "getElementById", "value", "substring", "picoCTF{", "not_this"];
```

It simply matches the element from that index and stores in `_0x4d74cb` which is also returned. Next, let's have a brief look at `verify()`.

If you notice, values like "0x0" and similar are simply numbers written in hex format.
So, updated version is:
```
function verify() {
    checkpass = document[_0x4b5b(0)]("pass")[_0x4b5b(1)];
    split = 4;
    if (checkpass[_0x4b5b(2)](0, split * 2) == _0x4b5b(3)) {
        if (checkpass[_0x4b5b(2)](7, 9) == "{n") {
            if (checkpass[_0x4b5b(2)](split * 2, split * 2 * 2) == _0x4b5b(4)) {
                if (checkpass[_0x4b5b(2)](3, 6) == "oCT") {
                    if (checkpass[_0x4b5b(2)](split * 3 * 2, split * 4 * 2) == _0x4b5b(5)) {
                        if (checkpass.substring(6, 11) == "F{not") {
                            if (checkpass[_0x4b5b(2)](split * 2 * 2, split * 3 * 2) == _0x4b5b(6)) {
                                if (checkpass[_0x4b5b(2)](12, 16) == _0x4b5b(7)) {
                                    alert(_0x4b5b(8));
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        alert(_0x4b5b(9));
    }
}
```

Now, also notice that when we have function `_0x4b5b(2)` this means `_0x5a46[2]`.
So, once again let's deobfuscate further:
```
function verify() {
    checkpass = document[_0x4b5b(0)]("pass")[_0x4b5b(1)];
    split = 4;
    if (checkpass[_0x4b5b(2)](0, split * 2) == _0x4b5b(3)) {
        if (checkpass[_0x4b5b(2)](7, 9) == "{n") {
            if (checkpass[_0x4b5b(2)](split * 2, split * 2 * 2) == _0x4b5b(4)) {
                if (checkpass[_0x4b5b(2)](3, 6) == "oCT") {
                    if (checkpass[_0x4b5b(2)](split * 3 * 2, split * 4 * 2) == _0x4b5b(5)) {
                        if (checkpass.substring(6, 11) == "F{not") {
                            if (checkpass[_0x4b5b(2)](split * 2 * 2, split * 3 * 2) == _0x4b5b(6)) {
                                if (checkpass[_0x4b5b(2)](12, 16) == _0x4b5b(7)) {
                                    alert(_0x4b5b(8));
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        alert(_0x4b5b(9));
    }
}
```


**Flag**:

**Learnings**: