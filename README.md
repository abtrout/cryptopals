# cryptopals

I'm working through the Matasano [crypto challenges](http://cryptopals.com) and keeping my work here. Everything is in scala. Solutions are written as unit tests. 

* Test specs are in [src/test/scala](https://github.com/abtrout/cryptopals/tree/master/src/test/scala)
* Utility methods are in [src/main/scala/utils](https://github.com/abtrout/cryptopals/tree/master/src/main/scala/utils) 

Run them with `sbt`:
```
> test-only net.logitank.cryptopals.Set1Tests
[info] Set1Tests
[info] 
[info] challenge1 should
[info] + convert given hex input to desired base64 output
[info] 
[info] challenge2 should
[info] + compute fixed XOR of two equal-length buffers
[info] 
[info] challenge3 should
[info] + find key to reverse single-character XOR
[info] + decode by single-character XORing with key
[info] 
[info] challenge4 should
[info] + find line from file that was encoded with single-character XOR
[info] 
[info] challenge5 should
[info] + encode string using repeating-key XOR
[info] 
[info] challenge6 should
[info] + compute Hamming distance of two strings
[info] 
[info] Total for specification Set1Tests
[info] Finished in 35 ms
[info] 7 examples, 0 failure, 0 error
[info] Passed: Total 7, Failed 0, Errors 0, Passed 7
[success] Total time: 2 s, completed Oct 11, 2014 11:19:39 PM
> 
```
