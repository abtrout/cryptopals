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

  //"challenge19" should {}
  //"challenge20" should {}
  //"challenge21" should {}
  //"challenge22" should {}
  //"challenge23" should {}
  //"challenge24" should {}
}
