package net.logitank.cryptopals

import org.specs2.mutable.Specification
import scala.io.Source

class Set2 extends Specification {
  
  "challenge9" should {
    "implement PKCS#7 padding" in {
      import CryptoUtil.Padding._
      "YELLOW SUBMARINE".pkcs7(20) mustEqual "YELLOW SUBMARINE\u0004\u0004\u0004\u0004"
    }
  }

  "challenge10" should {
    "encrypt ECB mode" in {
      val key = "YELLOW SUBMARINE"
      val plaintext = "We all live in aYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"
      val ciphertext = AES.ECB.encrypt(plaintext, key)

      AES.ECB.decrypt(ciphertext, key) mustEqual plaintext
    }

    "implement CBC mode" in {
      lazy val ciphertext = Base64Util.decode {
        Source.fromURL(getClass.getResource("/challenge-data/10.txt")).mkString
      }

      val key = "YELLOW SUBMARINE"
      val IV = "\u0000" * key.length

      val plaintext = AES.CBC.decrypt(ciphertext, key, IV)
      plaintext must startWith("I'm back and I'm ringin' the bell")
    }
  }

  //"challenge11" should {}
  //"challenge12" should {}
  //"challenge13" should {}
  //"challenge14" should {}
  //"challenge15" should {}
  //"challenge16" should {}
}
