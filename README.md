# cryptopals

I'm working through the Matasano [crypto challenges](http://cryptopals.com) and keeping my work here. If you're working on the challenges yourself, resist the urge to peek at solutions! Struggling on your own is beneficial.

Everything is in scala. Solutions are written as unit tests. 
* Test specs are in [src/test/scala](https://github.com/abtrout/cryptopals/tree/master/src/test/scala)
* Utility methods are in [src/main/scala/utils](https://github.com/abtrout/cryptopals/tree/master/src/main/scala/utils) 
* Run them with `sbt`

```
> test-only net.logitank.cryptopals.Set1
[info] Set1
[info] 
[info] challenge1 should
[info] + convert hex to base64
[info] 
[info] challenge2 should
[info] + compute fixed XOR
[info] 
[info] challenge3 should
[info] + find key from single-byte XOR
[info] + decrypt single-byte XOR
[info] 
[info] challenge4 should
[info] + detect single-character XOR
[info] 
[info] challenge5 should
[info] + implement repeating-key XOR
[info] 
[info] challenge6 should
[info] + determine keysize from repeating-key XOR
[info] + find key
[info] + decode plaintext
[info] 
[info] challenge7 should
[info] + decrypt AES-128 ECB
[info] 
[info] challenge8 should
[info] + detect AES-ECB
[info] 
[info] Total for specification Set1
[info] Finished in 37 ms
[info] 11 examples, 0 failure, 0 error
[info] Passed: Total 11, Failed 0, Errors 0, Passed 11
[success] Total time: 2 s, completed Oct 24, 2014 9:09:04 PM
> 
```
