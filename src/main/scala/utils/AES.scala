package net.logitank.cryptopals.AES

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

import net.logitank.cryptopals.Padding._

object CBC {

  private def fixedXOR(as: Array[Byte], bs: Array[Byte]): Array[Byte] =
    as.zip(bs).map(ab => (ab._1 ^ ab._2).toByte)

  def encrypt(pbytes: Array[Byte], kbytes: Array[Byte], iv: Array[Byte]) = {
    val blocks =
      pbytes.pkcs7(kbytes.length)
        .grouped(kbytes.length)
        .foldLeft(List(iv)) { (cs, p) =>
          val input = fixedXOR(cs.head, p)
          ECB.encrypt(input, kbytes) :: cs
        }

    blocks.reverse.tail.flatten.toArray
  }

  def decrypt(cbytes: Array[Byte], kbytes: Array[Byte], iv: Array[Byte]) = {
    (iv ++ cbytes)
      .grouped(kbytes.length).sliding(2)
      .flatMap { x =>
        val Seq(previousBlock, currentBlock) = x
        fixedXOR(ECB.decrypt(currentBlock, kbytes), previousBlock)
      }
  }
}

object ECB {
  // NB: This implements AES-128 ECB, which is bad crypto. Don't use it!
  // This is for a cryptopals (http://cryptopals.com) challenge.

  def encrypt(plaintext: String, key: String): String = {
    val pbytes = plaintext.toCharArray.map(_.toByte)
    val kbytes = key.toCharArray.map(_.toByte)

    encrypt(pbytes, kbytes).map(_.toChar).mkString
  }

  def encrypt(pbytes: Array[Byte], kbytes: Array[Byte]) = {
    val key = new SecretKeySpec(kbytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")

    cipher.init(Cipher.ENCRYPT_MODE, key)
    cipher.doFinal(pbytes)
  }

  def decrypt(ciphertext: String, key: String): String = {
    val cbytes = ciphertext.toCharArray.map(_.toByte)
    val kbytes = key.toCharArray.map(_.toByte)

    decrypt(cbytes, kbytes).map(_.toChar).mkString
  }

  def decrypt(cbytes: Array[Byte], kbytes: Array[Byte]) = {
    val key = new SecretKeySpec(kbytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")

    cipher.init(Cipher.DECRYPT_MODE, key)
    cipher.doFinal(cbytes)
  }
}

