# cryptopals

I'm working on the [Matasano Crypto Challenges](http://cryptopals.com), writing my solutions at unit tests in Scala.

Run them with `sbt`.

```bash
$ sbt
> test-only net.logitank.cryptopals.Set3
[info] Set3
[info] 
[info] challenge17 should
[info] + detect valid/invalid PKCS#7 padding from ciphertext
[info] + determine ciphertext by CBC padding attack
[info] 
[info] challenge18 should
[info] + decrypt AES CTR
[info] + encrypt AES CTR
[info] 
[info] challenge19 should
[info] + break fixed-nonce CTR using substitions
[info] 
[info] challenge20 should
[info] + break fixed-nonce CTR statistically
[info] 
[info] challenge21 should
[info] + implement MT19937 PRNG
[info] 
[info] challenge22 should
[info] + crack an MT19937 seed by brute force
[info] 
[info] challenge23 should
[info] + untemper MT19937 output to find internal state
[info] + clone an MT19937 PRNG from its output
[info] 
[info] challenge24 should
[info] + implement stream cipher from MT19937 PRNG
[info] + recover key from known plaintext/ciphertext
[info] 
[info] Total for specification Set3
[info] Finished in 14 ms
[info] 12 examples, 0 failure, 0 error
[info] Passed: Total 12, Failed 0, Errors 0, Passed 12
[success] Total time: 6 s, completed Nov 9, 2015 8:47:51 PM
```
