package net.logitank.cryptopals

import org.specs2.mutable.Specification

class UtilSpec extends Specification {

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
}
