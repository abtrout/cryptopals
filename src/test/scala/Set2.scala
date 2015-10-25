package net.logitank.cryptopals

import org.specs2.mutable.Specification
import scala.io.Source
import scala.util.Random

import net.logitank.cryptopals.Padding._

class Set2 extends Specification {
  
  "challenge9" should {
    "implement PKCS#7 padding" in {
      val key = "YELLOW SUBMARINE"
      val kbytes = "YELLOW SUBMARINE".toCharArray.map(_.toByte)
      val paddedKey = "YELLOW SUBMARINE\u0004\u0004\u0004\u0004"
      val paddedBytes = paddedKey.toCharArray.map(_.toByte)

      kbytes.padPKCS7(20) mustEqual paddedBytes
      kbytes.padPKCS7(16).length mustEqual 32
      kbytes.padPKCS7(16).unpadPKCS7.length mustEqual kbytes.length
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

      val pbytes: Array[Byte] = AES.CBC.decrypt(cbytes, kbytes, iv)
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
      val input = pbytes.padPKCS7(kbytes.length)

      Random.nextBoolean match {
        case false =>
          val input = pbytes.padPKCS7(kbytes.length)
          ("ECB", AES.ECB.encrypt(input, kbytes))
        case true =>
          val iv = randBytes(kbytes.length)
          ("CBC", AES.CBC.encrypt(pbytes, kbytes, iv))
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
      val input = pbytes.padPKCS7(kbytes.length)
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

      val index = (-128 to 127).map { k =>
        val cbytes = ecbOracle(base + k.toChar)
        (k.toChar, cbytes.take(blocksize).toList)
      } toMap

      val plaintext =
        unknownBytes.flatMap { b =>
          val cbytes = ecbOracle(base + b.toChar).take(blocksize).toList
          index.find(k => k._2 == cbytes).map(_._1)
        } mkString

      plaintext mustEqual unknownString
    }
  }

  "challenge13" should {
    def encodeParams(params: Map[String, String]) =
      params.toList.map(p => s"${p._1}=${p._2}").mkString("&")

    def decodeParams(params: String) =
      params.split('&').flatMap {
        _.split('=').toList match {
          case key :: value :: _ => Some((key, value))
          case key :: _ => Some((key, ""))
          case Nil => None
        }
      } toMap

    "decode parameter String to Map" in {
      val paramString = "a=1&b=2&c="
      val paramMap = Map(
        "a" -> "1",
        "b" -> "2",
        "c" -> "")

      decodeParams(paramString) mustEqual paramMap
      encodeParams(paramMap) mustEqual paramString
    }

    val blocksize = 16
    // knowledge of the key is assumed 
    val kbytes = randBytes(blocksize)

    def profileFor(email: String) = {
      val profile = Map(
        "email" -> email.split("&|=")(0), 
        "uid" -> "10",
        "role" -> "user")

      val pbytes =
        encodeParams(profile)
          .toCharArray.map(_.toByte)
          .padPKCS7(blocksize)

      AES.ECB.encrypt(pbytes, kbytes)
    }

    def profileFrom(cbytes: Array[Byte]) = {
      val pbytes = AES.ECB.decrypt(cbytes, kbytes)
      // I didn't build PKCS#7 into ECB, so we manually unpad
      pbytes.unpadPKCS7.map(_.toChar).mkString
    }

    "get user profile by email address" in {
      val params = "email=foo@bar.com&uid=10&role=user"

      // This also tests profileFrom (AES), and profileFor (AES)
      profileFrom(profileFor("foo@bar.com&role=admin")) mustEqual params
      profileFrom(profileFor("foo@bar.com")) mustEqual params
    }

    "create admin profile by ECB cut-and-paste attack" in {
      // 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
      // email=foooo@bar. com&uid=10&role= user
      // email=AAAAAAAAAA admin&uid=10&rol e=user
      // email=foooo@bar. com&uid=10&role= admin&uid=10&rol e=user
      val cbytes: Array[Byte] =
        profileFor("foooo@bar.com").slice(0, 2*blocksize) ++
        profileFor("AAAAAAAAAAadmin").drop(blocksize)

      profileFrom(cbytes) mustEqual "email=foooo@bar.com&uid=10&role=admin&uid=10&role=user" 
    }
  }

  "challenge14" should {
    val unknownString = Base64Util.decode {
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
      "YnkK"
    }

    val blocksize = 16
    val unknownBytes = unknownString.toCharArray.map(_.toByte)
    val kbytes = randBytes(blocksize)

    def ecbOracle(plaintext: String) = {
      val pbytes = {
        // Prepend up to one block of random bytes
        randBytes(Random.nextInt(16)) ++
        plaintext.toCharArray.map(_.toByte) ++
        unknownBytes
      }

      val input = pbytes.padPKCS7(kbytes.length)
      AES.ECB.encrypt(input, kbytes)
    }

    "decrypt ECB one byte at a timer with random prefix" in {
      // One thing we can do is reliably generate blocks of a
      // repeated single value, so we do that.
      val index = (-128 to 127).map { k =>
        val cbytes = ecbOracle(("" + k.toChar) * (2 * blocksize))
        (k.toChar, cbytes.slice(blocksize, 2 * blocksize).toList)
      } toMap

      val plaintext = unknownBytes.flatMap { b =>
        val cbytes = ecbOracle(("" + b.toChar) * (2 * blocksize))
          .slice(blocksize, 2 * blocksize).toList

        index.find(k => k._2 == cbytes).map(_._1)
      } mkString

      plaintext mustEqual unknownString
    }
  }

  "challenge15" should {
    "remove valid PKCS#7 padding" in {
      val str = "ICE ICE BABY\u0004\u0004\u0004\u0004"
      val valid = str.toCharArray.map(_.toByte).unpadPKCS7
      valid.map(_.toChar).mkString mustEqual("ICE ICE BABY")
    }

    "throw Exception on invalid PKCS#7 padding" in {
      val str = "ICE ICE BABY\u0005\u0005\u0005\u0005"
      val invalid = str.toCharArray.map(_.toByte)
      invalid.unpadPKCS7 must throwA(new Exception("Invalid PKCS#7 padding"))
    }
  }

  //"challenge16" should {}
}
