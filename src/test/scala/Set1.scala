package net.logitank.cryptopals

import org.specs2.mutable.Specification
import scala.io.Source

class Set1 extends Specification {

  "challenge1" should {
    "convert hex to base64" in {
      val input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
      val encoded = Base64Util.encode(HexUtil.toBytes(input))

      encoded mustEqual "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    }
  }

  "challenge2" should {
    "compute fixed XOR" in {
      val as = HexUtil.toBytes("1c0111001f010100061a024b53535009181c")
      val bs = HexUtil.toBytes("686974207468652062756c6c277320657965")
      val fixedXOR = HexUtil.fromBytes(as.zip(bs).map(ab => (ab._1 ^ ab._2).toByte))

      fixedXOR mustEqual "746865206b696420646f6e277420706c6179"
    }
  }

  def rankGuess(k: Char, bytes: Array[Byte]) = {
    val guess = bytes.map(b => (b ^ k).toChar).mkString
    // note: "uldrhs nioate" = "etaoin shrdlu".reverse
    guess.foldLeft(0)((r,c) => r + "uldrhs nioate".indexOf(c) + 1)
  }

  "challenge3" should {
    val encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    val bytes = HexUtil.toBytes(encoded)

    "find key from single-byte XOR" in {
      val guesses = (32 to 126).map(k => (k.toChar, rankGuess(k.toChar, bytes)))
      val key = guesses.maxBy(_._2)._1

      key mustEqual 'X'
    }

    "decrypt single-byte XOR" in {
      val key = 'X'.toByte
      val fixedXOR = bytes.map(b => (b ^ key).toChar).mkString

      fixedXOR mustEqual "Cooking MC's like a pound of bacon"
    }
  }

  "challenge4" should {
    "detect single-character XOR" in {
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
    "implement repeating-key XOR" in {
      val input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
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
    val input = Base64Util.decode {
      Source.fromURL(getClass.getResource("/challenge-data/6.txt")).getLines.mkString
    }

    "determine keysize from repeating-key XOR" in {
      val numBlocks = 5
      val keysize = (2 to 40).map(k => {
        val blocks = input.grouped(k).take(numBlocks).toList
        val avg = (0 until numBlocks-1).flatMap(i => {
          (i+1 until numBlocks).map(j => Hamming.distance(blocks(i), blocks(j)))
        }).sum / (2*k)

        (k, avg)
      }).minBy(_._2)._1

      keysize mustEqual 29
    }

    "find key" in {
      val keysize = 29
      val blockLength = input.length / keysize

      val key = (0 until keysize).map(i => {
        val block = (0 until blockLength).map(j => input.charAt(i + (j*keysize)).toByte).toArray
        (32 to 126).map(k => (k.toChar, rankGuess(k.toChar, block))).maxBy(_._2)._1
      }).mkString

      key mustEqual "Terminator X: Bring the noise"
    }

    "decode plaintext" in {
      val key = "Terminator X: Bring the noise"
      val plaintext = input.zipWithIndex.map(x => {
        (x._1.toByte ^ key.charAt(x._2 % key.length)).toChar
      }).mkString

      plaintext mustEqual Lyrics.playThatFunkyMusic
    }
  }

  "challenge7" should {
    "decrypt AES-128 ECB" in {
      val input = Base64Util.decode {
        Source.fromURL(getClass.getResource("/challenge-data/7.txt")).mkString
      }

      val key = "YELLOW SUBMARINE"
      val plaintext = AES.ECB.decrypt(input, key)

      plaintext mustEqual Lyrics.playThatFunkyMusic
    }
  }

  "challenge8" should {
    "detect AES-ECB" in {
      val lines = Source.fromURL(getClass.getResource("/challenge-data/8.txt")).getLines
      val line = lines.map(l => {
        // note: finding duplicate 16 byte ciphertext blocks is the same as
        // finding duplicate 32 byte hex encodings of the same ciphertext
        val blocks = l.grouped(32).toList

        (l, (blocks.length - blocks.distinct.length))
      }).maxBy(_._2)._1

      line mustEqual "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    }
  }
}

object Lyrics {
  val playThatFunkyMusic = Seq(
    "I'm back and I'm ringin' the bell ",
    "A rockin' on the mike while the fly girls yell ",
    "In ecstasy in the back of me ",
    "Well that's my DJ Deshay cuttin' all them Z's ",
    "Hittin' hard and the girlies goin' crazy ",
    "Vanilla's on the mike, man I'm not lazy. ",
    "",
    "I'm lettin' my drug kick in ",
    "It controls my mouth and I begin ",
    "To just let it flow, let my concepts go ",
    "My posse's to the side yellin', Go Vanilla Go! ",
    "",
    "Smooth 'cause that's the way I will be ",
    "And if you don't give a damn, then ",
    "Why you starin' at me ",
    "So get off 'cause I control the stage ",
    "There's no dissin' allowed ",
    "I'm in my own phase ",
    "The girlies sa y they love me and that is ok ",
    "And I can dance better than any kid n' play ",
    "",
    "Stage 2 -- Yea the one ya' wanna listen to ",
    "It's off my head so let the beat play through ",
    "So I can funk it up and make it sound good ",
    "1-2-3 Yo -- Knock on some wood ",
    "For good luck, I like my rhymes atrocious ",
    "Supercalafragilisticexpialidocious ",
    "I'm an effect and that you can bet ",
    "I can take a fly girl and make her wet. ",
    "",
    "I'm like Samson -- Samson to Delilah ",
    "There's no denyin', You can try to hang ",
    "But you'll keep tryin' to get my style ",
    "Over and over, practice makes perfect ",
    "But not if you're a loafer. ",
    "",
    "You'll get nowhere, no place, no time, no girls ",
    "Soon -- Oh my God, homebody, you probably eat ",
    "Spaghetti with a spoon! Come on and say it! ",
    "",
    "VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino ",
    "Intoxicating so you stagger like a wino ",
    "So punks stop trying and girl stop cryin' ",
    "Vanilla Ice is sellin' and you people are buyin' ",
    "'Cause why the freaks are jockin' like Crazy Glue ",
    "Movin' and groovin' trying to sing along ",
    "All through the ghetto groovin' this here song ",
    "Now you're amazed by the VIP posse. ",
    "",
    "Steppin' so hard like a German Nazi ",
    "Startled by the bases hittin' ground ",
    "There's no trippin' on mine, I'm just gettin' down ",
    "Sparkamatic, I'm hangin' tight like a fanatic ",
    "You trapped me once and I thought that ",
    "You might have it ",
    "So step down and lend me your ear ",
    "'89 in my time! You, '90 is my year. ",
    "",
    "You're weakenin' fast, YO! and I can tell it ",
    "Your body's gettin' hot, so, so I can smell it ",
    "So don't be mad and don't be sad ",
    "'Cause the lyrics belong to ICE, You can call me Dad ",
    "You're pitchin' a fit, so step back and endure ",
    "Let the witch doctor, Ice, do the dance to cure ",
    "So come up close and don't be square ",
    "You wanna battle me -- Anytime, anywhere ",
    "",
    "You thought that I was weak, Boy, you're dead wrong ",
    "So come on, everybody and sing this song ",
    "",
    "Say -- Play that funky music Say, go white boy, go white boy go ",
    "play that funky music Go white boy, go white boy, go ",
    "Lay down and boogie and play that funky music till you die. ",
    "",
    "Play that funky music Come on, Come on, let me hear ",
    "Play that funky music white boy you say it, say it ",
    "Play that funky music A little louder now ",
    "Play that funky music, white boy Come on, Come on, Come on ",
    "Play that funky music ",
    ""
  ).mkString("\n")
}
