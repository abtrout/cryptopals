package net.logitank.cryptopals

import org.specs2.mutable.Specification
import scala.io.Source
import scala.util.Random

import net.logitank.cryptopals.Padding._

class Set2 extends Specification {
  
  "challenge9" should {
    "implement PKCS#7 padding" in {
      val key = "YELLOW SUBMARINE"
      val kbytes = key.toCharArray.map(_.toByte)

      val paddedKey = "YELLOW SUBMARINE\u0004\u0004\u0004\u0004"
      val paddedBytes = paddedKey.toCharArray.map(_.toByte)

      key.pkcs7(20) mustEqual paddedKey
      kbytes.pkcs7(20) mustEqual paddedBytes
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

      val cbytes = ciphertext.toCharArray.map(_.toByte)
      val kbytes = "YELLOW SUBMARINE".getBytes
      val iv = Array.fill[Byte](kbytes.length)(0.toByte)

      val pbytes = AES.CBC.decrypt(cbytes, kbytes, iv)
      val plaintext = pbytes.map(_.toChar).mkString

      plaintext must startWith("I'm back and I'm ringin' the bell")
    }
  }

  "challenge11" should {
    // Using Kestrel combinator <http://stackoverflow.com/a/9673294>
    def kestrel[A](x: A)(f: A => Unit): A = { f(x); x }
    def randBytes(k: Int) = kestrel(Array.fill[Byte](k)(0))(Random.nextBytes)

    def encryptionOracle(plaintext: String) = {
      val pbytes = {
        randBytes(Random.nextInt(6) + 5) ++
        plaintext.toCharArray.map(_.toByte) ++
        randBytes(Random.nextInt(6) + 5)
      }

      val kbytes = randBytes(16)
      val input = pbytes.pkcs7(kbytes.length)

      Random.nextBoolean match {
        case false => ("ECB", AES.ECB.encrypt(input, kbytes))
        case true =>
          val iv = randBytes(kbytes.length)
          ("CBC", AES.CBC.encrypt(input, kbytes, iv))
      }
    }

    "detect block cipher from encryption oracle" in {
      val (mode, cbytes) = encryptionOracle("A" * 256)
      // Note: converting our List[Array[_]] to List[List[_]] so that we
      // can make comparisons and use .distinct below
      val blocks = cbytes.grouped(16).toList.map(_.toList)
      val guess =  if(blocks.length == blocks.toSet.size) "CBC" else "ECB"

      guess mustEqual mode
    }
  }

  //"challenge12" should {}
  //"challenge13" should {}
  //"challenge14" should {}
  //"challenge15" should {}
  //"challenge16" should {}
}
