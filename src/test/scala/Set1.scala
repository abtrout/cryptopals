package net.logitank.cryptopals

import org.specs2.mutable.Specification

class Set1Tests extends Specification {
  
  "challenge1" should {
    "convert given hex input to desired base64 output" in {
      val input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
      val bytes = HexUtil.toBytes(input)

      val answer = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
      Base64Util.encode(bytes) mustEqual answer
    }
  }

  "challenge2" should {
    "compute fixed XOR of two equal-length buffers" in {
      val as = HexUtil.toBytes("1c0111001f010100061a024b53535009181c")
      val bs = HexUtil.toBytes("686974207468652062756c6c277320657965")
      val fixedXOR = as.zip(bs).map(ab => (ab._1 ^ ab._2).toByte)

      val answer = "746865206b696420646f6e277420706c6179"
      HexUtil.fromBytes(fixedXOR) mustEqual answer
    }
  }
      
  def rankGuess(k: Char, bytes: Array[Byte]) = {
    val guess = bytes.map(b => (b ^ k).toChar).mkString
    // note that "uldrhs nioate" = "etaoin shrdlu".reverse
    guess.foldLeft(0)((r,c) => r + "uldrhs nioate".indexOf(c) + 1)
  }

  "challenge3" should {
    val encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    val bytes = HexUtil.toBytes(encoded)

    "find key to reverse single-character XOR" in {
      val guesses = (32 to 126).map(k => (k.toChar, rankGuess(k.toChar, bytes)))
      val key = guesses.maxBy(_._2)._1
      key mustEqual 'X'
    }

    "decode by single-character XORing with key" in {
      val key = 'X'.toByte
      val fixedXOR = bytes.map(b => (b ^ key).toChar).mkString
      fixedXOR mustEqual "Cooking MC's like a pound of bacon"
    }
  }

  "challenge4" should {
    import scala.io.Source

    "find line from file that was encoded with single-character XOR" in {
      val lines = Source.fromURL(getClass.getResource("/challenge-data/4.txt")).getLines
      val (key, line, _) = lines.flatMap(line => {
        val bytes = HexUtil.toBytes(line)
        (32 to 126).map(k => (k.toChar, line, rankGuess(k.toChar, bytes))) 
      }).maxBy(_._3)

      key mustEqual '5'

      val decoded = HexUtil.toBytes(line).map(b => (b ^ key.toByte).toChar).mkString
      decoded mustEqual "Now that the party is jumping\n"
    }
  }

  "challenge5" should {
    "encode string using repeating-key XOR" in {
      val input = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
      val key = "ICE".getBytes

      val bytes = input.getBytes.zipWithIndex.map(bi => {
        val (b,i) = bi
        (b ^ key(i % key.length)).toByte
      })

      val answer = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
      HexUtil.fromBytes(bytes) mustEqual answer
    }
  }

  "challenge6" should {
    "compute Hamming distance of two strings" in {
      Hamming.distance("this is a test", "wokka wokka!!!") mustEqual 37
    }
  }

}
