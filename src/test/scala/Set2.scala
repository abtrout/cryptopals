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

  // Using Kestrel combinator <http://stackoverflow.com/a/9673294>
  def kestrel[A](x: A)(f: A => Unit): A = { f(x); x }
  def randBytes(k: Int) = kestrel(Array.fill[Byte](k)(0))(Random.nextBytes)

  "challenge11" should {
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

  "challenge12" should {
    val unknownString = Base64Util.decode {
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
      "YnkK"
    }

    val unknownBytes = unknownString.toCharArray.map(_.toByte)
    val kbytes = randBytes(16)

    def ecbOracle(plaintext: String) = {
      val pbytes = plaintext.toCharArray.map(_.toByte) ++ unknownBytes
      val input = pbytes.pkcs7(kbytes.length)
      AES.ECB.encrypt(input, kbytes)
    }

    "detect block size from ciphertext" in {
      val base = ecbOracle("").length
      def tryBlock(n: Int): Int = {
        val len = ecbOracle("A" * n).length
        if(len > base) len - base
        else tryBlock(n+1)
      }

      val blocksize = tryBlock(1)
      blocksize mustEqual 16
    }

    "detect ECB mode from ciphertext" in {
      val blocksize = 16
      val cbytes = ecbOracle("A" * (blocksize * 10))
      val blocks = cbytes.grouped(blocksize).toList.map(_.toList)

      blocks.length - blocks.toSet.size must be greaterThan(0)
    }

    "decrypt ciphertext one block at a time" in {
      val blocksize = 16
      val base = "A" * (blocksize - 1)

      val plaintext =
        unknownBytes.flatMap { b =>
          val index = (-128 to 127).map { k =>
            val cbytes = ecbOracle(base + k.toChar)
            (k.toChar, cbytes.take(blocksize).toList)
          } toMap

          val cbytes = ecbOracle(base + b.toChar).take(blocksize).toList
          index.find(k => k._2 == cbytes).map(_._1)
        } mkString

      plaintext mustEqual unknownString
    }
  }

  //"challenge13" should {}
  //"challenge14" should {}
  //"challenge15" should {}
  //"challenge16" should {}
}
