package net.logitank.cryptopals

import org.specs2.mutable.Specification

class UtilSpec extends Specification {

  "Base64Util" should {
    "encode string to base64" in {
      Base64Util.encode("cryptopals for life") mustEqual "Y3J5cHRvcGFscyBmb3IgbGlmZQ=="
    }
  }

  "Hamming" should {
    "compute Hamming distance" in {
      Hamming.distance("abcdefg", "abcdefg") mustEqual 0  
      Hamming.distance("this is a test", "wokka wokka!!!") mustEqual 37
    }
  }
}
