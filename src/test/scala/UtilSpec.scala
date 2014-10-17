package net.logitank.cryptopals

import org.specs2.mutable.Specification

class UtilSpec extends Specification {

  "Base64Util" should {
    "encode string to base64" in {
      Base64Util.encode("cryptopals for life") mustEqual "Y3J5cHRvcGFscyBmb3IgbGlmZQ=="
    }

    "decode string from base64" in {
      Base64Util.decode("Y3J5cHRvcGFscyBmb3IgbGlmZQ==") mustEqual "cryptopals for life"
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
