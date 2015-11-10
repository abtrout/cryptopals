package net.logitank.cryptopals

import org.specs2.mutable.Specification
import scala.annotation.tailrec
import scala.io.Source
import scala.util.{Random, Success, Try}

import net.logitank.cryptopals.Padding._

class Set3 extends Specification {

  def kestrel[A](x: A)(f: A => Unit): A = { f(x); x }
  def randBytes(k: Int) = kestrel(Array.fill[Byte](k)(0))(Random.nextBytes)

  "challenge17" should {

    val plaintexts = Vector(
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ).map(Base64Util.decode)

    val blocksize = 16
    val kbytes = randBytes(blocksize)

    def getCiphertext = {
      val iv = randBytes(blocksize)
      val pbytes =
        plaintexts(Random.nextInt(plaintexts.length))
          .toCharArray.map(_.toByte)

      (iv, AES.CBC.encrypt(pbytes, kbytes, iv))
    }

    def hasValidPadding(cbytes: Array[Byte], iv: Array[Byte]): Boolean = {
      // Our CBC implementation includes padding, so we just need
      // to catch the Exception if one is thrown
      Try(AES.CBC.decrypt(cbytes, kbytes, iv)) match {
        case Success(_) => true
        case _ => false
      }
    }

    "detect valid/invalid PKCS#7 padding from ciphertext" in {
      val (iv, cbytes) = getCiphertext
      hasValidPadding(cbytes, iv) mustEqual true

      cbytes(cbytes.length - 1) = 10.toByte
      hasValidPadding(cbytes, iv) mustEqual false
    }

    "determine ciphertext by CBC padding attack" in {

      val (iv, cbytes) = getCiphertext

      def attackBlock(lastBlock: Array[Byte], nextBlock: Array[Byte]): Array[Byte] = {
        val int = Array.fill[Byte](blocksize)(0.toByte)

        (1 to blocksize).foreach { padlen =>
          val pad = Array.fill[Byte](blocksize - padlen)(0.toByte).padPKCS7(blocksize)
          val tmp = XORUtil.fixedXOR(pad, int)

          def findByte(j: Int = 0): Int = {
            tmp(blocksize - padlen) = j.toByte
            if(hasValidPadding(tmp ++ nextBlock, iv) || j >= 256) j
            else findByte(j + 1)
          }

          int(blocksize - padlen) = (findByte() ^ padlen).toByte
        }

        XORUtil.fixedXOR(int, lastBlock)
      }

      val pbytes: Array[Byte] =
        XORUtil.fixedXOR(AES.ECB.decrypt(cbytes.slice(0, blocksize), kbytes), iv) ++
        cbytes.grouped(blocksize).take(blocksize - 1)
          .zip(cbytes.grouped(blocksize).drop(1))
          .flatMap(blocks => attackBlock(blocks._1, blocks._2))
          .toArray.unpadPKCS7

      val plaintext = pbytes.map(_.toChar).mkString
      plaintexts.find(_ == plaintext) must beSome
    }
  }

  "challenge18" should {

    "decrypt AES CTR" in {
      val ciphertext = Base64Util.decode(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

      val nonce = Array.fill[Byte](8)(0.toByte)
      val kbytes = "YELLOW SUBMARINE".toCharArray.map(_.toByte)
      val cbytes = ciphertext.toCharArray.map(_.toByte)

      val pbytes = AES.CTR.decrypt(cbytes, kbytes, nonce)
      val plaintext = pbytes.map(_.toChar).mkString

      plaintext mustEqual "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    }

    "encrypt AES CTR" in {
      val nonce = Array.fill[Byte](8)(0.toByte)
      val kbytes = randBytes(16)
      val pbytes = "Meaningless Jibber Jabber".toCharArray.map(_.toByte)

      val cbytes = AES.CTR.encrypt(pbytes, kbytes, nonce)
      val plaintext =
        AES.CTR.decrypt(cbytes, kbytes, nonce)
          .map(_.toChar).mkString

      plaintext mustEqual "Meaningless Jibber Jabber"
    }
  }

  def rankGuess(k: Char, bytes: Array[Byte]) = {
    val guess = bytes.map(b => (b ^ k).toChar).mkString

    val monograms = "etaoin shrdlucmfgypwbvkxjqz".reverse
    val bigrams = List("th", "he", "in", "en", "nt", "re",
      "er", "an", "ti", "es", "on", "at", "se", "nd", "or",
      "ar", "al", "te", "co", "de", "to", "ra", "et", "ed",
      "it", "sa", "em", "ro").reverse

    val mg = guess.foldLeft(0)((r,c) => r + monograms.indexOf(c) + 1)
    val bg = guess.sliding(2).foldLeft(0)((r, c) => r + bigrams.indexOf(c) + 1)
    math.sqrt(math.pow(mg, 2) + math.pow(bg, 2))
  }

  "challenge19" should {

    val inputs = List(
      "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
      "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
      "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
      "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
      "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
      "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
      "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
      "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
      "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
      "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
      "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
      "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
      "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
      "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
      "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
      "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
      "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
      "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
      "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
      "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
      "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
      "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
      "U2hlIHJvZGUgdG8gaGFycmllcnM/",
      "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
      "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
      "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
      "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
      "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
      "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
      "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
      "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
      "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
      "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
      "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
      "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
      "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
      "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
      "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
      "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
      "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=")

    // Encrypt the Base64 decoded inputs under CTR with the same key and nonce
    val kbytes = randBytes(16)
    val nonce = Array.fill[Byte](8)(0.toByte)

    val ciphertexts = inputs.map { x =>
      val cbytes = Base64Util.decode(x).toCharArray.map(_.toByte)
      AES.CTR.encrypt(cbytes, kbytes, nonce)
    }

    "break fixed-nonce CTR using substitions" in {
      val max = ciphertexts.map(_.length).max - 1
      val key = (0 to max).toArray.map { i =>
        // Build a block consisting of every ith byte
        val bytes = ciphertexts.filter(_.length > i).map(_(i)).toArray
        // Rank guesses by frequency analysis on {1,2}grams
        (-127 to 128).map(k => (k.toChar, rankGuess(k.toChar, bytes)))
          .maxBy(_._2)._1.toByte
      }

      val plaintexts = ciphertexts.map { c =>
        XORUtil.fixedXOR(c, key).map(_.toChar).mkString
      }

      plaintexts.last mustEqual "a terrible beauty is born."
    }
  }

  // I used the same strategy for challenge 19
  // ¯\_(ツ)_/¯
  "challenge20" should {

    val kbytes = randBytes(16)
    val nonce = Array.fill[Byte](8)(0.toByte)

    val ciphertexts =
      Source.fromURL(getClass.getResource("/challenge-data/20.txt"))
        .getLines.toList.map { x =>
          val cbytes = Base64Util.decode(x).toCharArray.map(_.toByte)
          AES.CTR.encrypt(cbytes, kbytes, nonce)
        }

    "break fixed-nonce CTR statistically" in {
      val min = ciphertexts.map(_.length).min - 1
      val key = (0 to min).toArray.map { i =>
        val bytes = ciphertexts.map(_(i)).toArray
        (-127 to 128).map(k => (k.toChar, rankGuess(k.toChar, bytes)))
          .maxBy(_._2)._1.toByte
      }

      val plaintexts = ciphertexts.map { c =>
        XORUtil.fixedXOR(c, key).map(_.toChar).mkString
      }

      plaintexts.last mustEqual "and we outta here / Yo, what happened to peace? / Pea"
    }
  }

  "challenge21" should {
    "implement MT19937 PRNG" in {
      val r1 = new RandUtil.MT19937(17)
      val r2 = new RandUtil.MT19937(17)

      // Given the same seed, these should produce the same integers
      val matches = (0 to 1500).foldLeft(true) { (acc, i) =>
        acc && (r1.nextInt == r2.nextInt)
      }

      matches mustEqual true
    }
  }

  "challenge22" should {
    // Simulate a random delay between 40 and 1000 seconds
    val delay = 40000 + Random.nextInt(960000)
    val seed = System.currentTimeMillis.toInt - delay
    val r = new RandUtil.MT19937(seed)
    val x = r.nextInt

    def findSeed(ts: Int, dt: Int): Option[Int] = {
      if(dt > 0) {
        r.seedWith(ts - dt)

        if(r.nextInt == x) Some(ts - dt)
        else findSeed(ts, dt - 1)
      }
      else None
    }

    "crack an MT19937 seed by brute force" in {
      val ts = System.currentTimeMillis.toInt
      findSeed(ts, 1e6.toInt) mustEqual Some(seed)
    }
  }

  "challenge23" should {
    "untemper MT19937 output to find internal state" in {
      val mt = new RandUtil.MT19937
      val x = Random.nextInt
      mt.untemper(mt.temper(x)) mustEqual x
    }

    "clone an MT19937 PRNG from its output" in {
      val r1 = new RandUtil.MT19937(Random.nextInt)

      val mt = (1 to 624).map(_ => r1.untemper(r1.nextInt)).toArray
      val r2 = new RandUtil.MT19937(Random.nextInt, Some(mt))
      val matches = (0 to 1500).foldLeft(true) { (acc, _) =>
        acc && (r1.nextInt == r2.nextInt)
      }

      matches mustEqual true
    }
  }

  "challenge24" should {
    def encrypt(pbytes: Array[Byte], seed: Int): Array[Byte] = {
      val r = new RandUtil.MT19937(seed)
      // Note: converting from 32-bit Int to 8-bit Int by way of Byte
      pbytes.map(x => (x ^ (r.nextInt.toByte.toInt)).toByte)
    }

    def decrypt(cbytes: Array[Byte], seed: Int) = encrypt(cbytes, seed)

    "implement stream cipher from MT19937 PRNG" in {
      // Note: converting from 32-bit Int to 16-bit Int by way of Short
      val seed = Random.nextInt.toShort.toInt

      val plaintext = "We all live in a yellow submarine, yellow submarine, yellow submarine."
      val cbytes = encrypt(plaintext.toCharArray.map(_.toByte), seed)
      val pbytes = decrypt(cbytes, seed)

      pbytes.map(_.toChar).mkString mustEqual plaintext
    }

    def findSeed(pbytes: Array[Byte], cbytes: Array[Byte]): Option[Int] = {
      val padding = cbytes.length - pbytes.length

      def trySeed(x: Int): Option[Int] = {
        if(x > 32767) None
        else {
          val tmp = decrypt(cbytes, x).drop(padding)
          // TODO: Using .toList for comparison. Do something better.
          if(tmp.toList == pbytes.toList) Some(x)
          else trySeed(x + 1)
        }
      }

      trySeed(-32768)
    }

    "recover key from known plaintext/ciphertext" in {
      val seed = Random.nextInt.toShort.toInt
      val padding = randBytes(Random.nextInt(20))
      val pbytes = ("A" * 14).toCharArray.map(_.toByte)
      val cbytes = encrypt(padding ++ pbytes, seed)

      findSeed(pbytes, cbytes) must beSome(seed)
    }
  }
}
