
**Title**: Irish-Name-Repo

**Description**: 
There is a website running at `https://jupiter.challenges.picoctf.org/problem/50009/` ([link](https://jupiter.challenges.picoctf.org/problem/50009/)) or http://jupiter.challenges.picoctf.org:50009. Do you think you can log us in? Try to see if you can login!


**Steps Taken**:

Looking at it, it would be hard to understand where to look, but hint #1 points the vulnerability has something to do with the form.
So, the first thing you do is SQL injection.

Usually the query behind the scene might follow this structure:
```
SELECT * FROM users WHERE username = '' AND password = '';
```

Look below in the learnings section to understand in detail how it works.
But, I put username as `admin` which even if I left all fields blank would do it, but just for tp.

Then inserted this in the password:
```
' OR '1'='1
```

And voila! It returns the flag!

**Flag**: `picoCTF{s0m3_SQL_fb3fe2ad}`

**Learnings**:

In the beginning the query looks like this:
```
SELECT * FROM users WHERE username = '' AND password = '';
```

When you enter any username and password say 'admin':'admin', it will look like this in the query behind the scenes:
```
SELECT * FROM users WHERE username = 'admin' AND password = 'admin';
```

The `AND` makes sure that both conditions need to be true for it to work.
The strategy behind SQL Injection is to add an `OR` statement where we can manually add an obviously true statement cause F OR T = T.

For this we do:
```
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';
```

We added `' OR '1'='1`
Cause initially the username = '' was there.
To escape the `''` we add another `' `. So, now it becomes:
```
username = '' ' AND password = '';
```

Now let's add `OR ` to it:
```
username = '' OR ' AND password = '';
```

You can start to see it coming together.
Let's add an obviously true equation like `1 == 1`, but according to syntax we will add ` '1' = '1` to look like:
```
username = '' OR '1' = '1' AND password = '';
```

and not `'1' = '1'` cause:
```
username = '' OR '1' = '1'' AND password = '';
```

Hence, now looking at correct statement:
```
username = '' OR '1' = '1' AND password = '';
```

We can see that according to priority first AND will execute then OR.
So first, `username = '' AND password = ''` which comes to be false.
Now, `FALSE OR '1' = '1'` since `'1' = '1'` is true but in an `OR`, `False OR True = True`.
Which makes the statement true, and Voila! You're in!