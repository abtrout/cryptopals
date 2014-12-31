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

    def fixedXOR(a: String, b: String) = a.zip(b).map(ab => (ab._1 ^ ab._2).toByte)

    "implement CBC mode" in {
      lazy val cipherText = Base64Util.decode {
        Source.fromURL(getClass.getResource("/challenge-data/10.txt")).getLines.mkString
      }

      val key = "YELLOW SUBMARINE"
      val IV = "\u0000" * key.length


      val plainText = (IV + cipherText)
        .grouped(key.length).take(4).sliding(2)
        .map(x => {
          val Seq(previousBlock, currentBlock) = x

          fixedXOR(
            CryptoUtil.AES.decrypt(currentBlock, key),
            previousBlock
          )
        }).mkString

      plainText mustEqual "ASDF"
    }
  }

  //"challenge11" should {}
  //"challenge12" should {}
  //"challenge13" should {}
  //"challenge14" should {}
  //"challenge15" should {}
  //"challenge16" should {}
}
