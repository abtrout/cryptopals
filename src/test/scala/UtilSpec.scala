package net.logitank.cryptopals

import org.specs2.mutable.Specification

class Utils extends Specification {

  "Base64Util" should {
    "encode string to base64" in {
      Base64Util.encode("") mustEqual ""
      Base64Util.encode("f") mustEqual "Zg=="
      Base64Util.encode("fo") mustEqual "Zm8="
      Base64Util.encode("foo") mustEqual "Zm9v"
      Base64Util.encode("foob") mustEqual "Zm9vYg=="
      Base64Util.encode("fooba") mustEqual "Zm9vYmE="
      Base64Util.encode("foobar") mustEqual "Zm9vYmFy"
    }

    "decode string from base64" in {
      Base64Util.decode("") mustEqual ""
      Base64Util.decode("Zg==") mustEqual "f"
      Base64Util.decode("Zm8=") mustEqual "fo"
      Base64Util.decode("Zm9v") mustEqual "foo"
      Base64Util.decode("Zm9vYg==") mustEqual "foob"
      Base64Util.decode("Zm9vYmE=") mustEqual "fooba"
      Base64Util.decode("Zm9vYmFy") mustEqual "foobar"
    }
  }

  "Hamming" should {
    "compute Hamming distance" in {
      Hamming.distance("cryptopals", "cryptopals") mustEqual 0  
      Hamming.distance(Array(63.toByte), Array(31.toByte)) mustEqual 1
      Hamming.distance("this is a test", "wokka wokka!!!") mustEqual 37
    }
  }

  "XORUtil" should {

    def printBytes(xs: List[Int], n: Int): Unit =
      xs.foreach { x =>
        val binary = x.toBinaryString
        val bytes = "0" * (32 - binary.length) + binary
        println(bytes.grouped(n).mkString(" "))
      }

    "invert y = x ^ ((x >>> n) & c)" in {
      val success = (1 to 1000).foldLeft(true) { (acc, _) =>
        val n = scala.util.Random.nextInt(31) + 1
        val c = scala.util.Random.nextInt
        val x = scala.util.Random.nextInt
        val y = x ^ ((x >>> n) & c)

        acc && XORUtil.invertRightShiftAndXOR(y, c, n) == x
      }

      success mustEqual true
    }

    "invert y = x ^ ((x << n) & c)" in {
      val success = (1 to 1000).foldLeft(true) { (acc, _) =>
        val n = scala.util.Random.nextInt(31) + 1
        val c = scala.util.Random.nextInt
        val x = scala.util.Random.nextInt
        val y = x ^ ((x << n) & c)

        acc && XORUtil.invertLeftShiftAndXOR(y, c, n) == x
      }

      success mustEqual true
    }
  }
}
