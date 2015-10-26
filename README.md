# cryptopals

I'm working on the [Matasano Crypto Challenges](http://cryptopals.com), writing my solutions at unit tests in Scala.

Run them with `sbt`.

```bash
$ sbt
> test-only net.logitank.cryptopals.Set2
[info] Set2
[info] 
[info] challenge9 should
[info] + implement PKCS#7 padding
[info] 
[info] challenge10 should
[info] + encrypt ECB mode
[info] + implement CBC mode
[info] 
[info] challenge11 should
[info] + detect block cipher from encryption oracle
[info] 
[info] challenge12 should
[info] + detect block size from ciphertext
[info] + detect ECB mode from ciphertext
[info] + decrypt ciphertext one block at a time
[info] 
[info] challenge13 should
[info] + decode parameter String to Map
[info] + get user profile by email address
[info] + create admin profile by ECB cut-and-paste attack
[info] 
[info] challenge14 should
[info] + decrypt ECB one byte at a timer with random prefix
[info] 
[info] challenge15 should
[info] + remove valid PKCS#7 padding
[info] + throw Exception on invalid PKCS#7 padding
[info] 
[info] challenge16 should
[info] + generates User data
[info] + flip CBC bits to generate admin user
[info] 
[info] Total for specification Set2
[info] Finished in 58 ms
[info] 15 examples, 0 failure, 0 error
[info] Passed: Total 15, Failed 0, Errors 0, Passed 15
[success] Total time: 6 s, completed Oct 26, 2015 1:53:53 AM
```
