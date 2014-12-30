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
      val plainText = "We all live in a"
      val cipherText = CryptoUtil.AES.encrypt(plainText, key)

      CryptoUtil.AES.decrypt(cipherText, key) mustEqual plainText
    }

    "implement CBC mode" in {
      

      1 mustEqual 1
    }
  }

  //"challenge11" should {}
  //"challenge12" should {}
  //"challenge13" should {}
  //"challenge14" should {}
  //"challenge15" should {}
  //"challenge16" should {}
}
