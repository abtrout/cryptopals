package net.logitank.cryptopals

import org.specs2.mutable.Specification
import scala.util.Random
import scala.io.Source

object Set4 extends Specification {

  def kestrel[A](x: A)(f: A => Unit): A = { f(x); x }
  def randBytes(k: Int) = kestrel(Array.fill[Byte](k)(0))(Random.nextBytes)

  "challenge25" should {
    // For this challenge, we fix an unknown key and nonce.
    val kbytes = randBytes(16)
    val nonce = randBytes(8)

    val ctext = Base64Util.decode {
      Source.fromURL(getClass.getResource("/challenge-data/25.txt")).mkString
    }

    // This is the same file used in challenge 7. It's ECB encrypted with the key
    // "YELLOW SUBMARINE". We need to (ECB) decrypt it before continuing.
    val ptext = AES.ECB.decrypt(ctext, "YELLOW SUBMARINE")
    val pbytes = ptext.toCharArray.map(_.toByte)
    val cbytes = AES.CTR.encrypt(pbytes, kbytes, nonce)

    def edit(cbytes: Array[Byte], offset: Int, newBytes: Array[Byte]) = {
      val tmp = AES.CTR.decrypt(cbytes, kbytes, nonce)
      AES.CTR.encrypt(tmp.take(offset) ++ newBytes, kbytes, nonce)
    }

    "break random access read/write AES CTR" in {
      val stream = edit(cbytes, 0, Array.fill[Byte](cbytes.length)(0))
      val plaintext = XORUtil.fixedXOR(cbytes, stream).map(_.toChar).mkString

      plaintext must startWith("I'm back and I'm ringin' the bell")
    }
  }
}
