package net.logitank.cryptopals.AES

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object CBC {

  private def fixedXOR(a: String, b: String) =
    a.zip(b).map(ab => (ab._1 ^ ab._2).toByte)
  
  def decrypt(ctext: String, key: String, iv: String) = {
    (iv + ctext)
      .grouped(key.length).sliding(2)
      .flatMap(x => {
        val Seq(previousBlock, currentBlock) = x
        fixedXOR(ECB.decrypt(currentBlock, key), previousBlock)
      })
      .map(_.toChar).mkString
  }

  // def encrypt(ctext: String, key: String, iv: String) = {}
}

// NB: This implements AES-128 ECB, which is bad crypto. Don't use it!
// This is for a cryptopals (http://cryptopals.com) challenge.
object ECB {

  def encrypt(plaintext: String, key: String): String =
    encrypt(plaintext.map(_.toByte).toArray, key.getBytes).map(_.toChar).mkString

  def decrypt(ciphertext: String, key: String): String =
    decrypt(ciphertext.map(_.toByte).toArray, key.getBytes).map(_.toChar).mkString

  def encrypt(pbytes: Array[Byte], kbytes: Array[Byte]) = {
    val key = new SecretKeySpec(kbytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)

    cipher.doFinal(pbytes)
  }

  def decrypt(cbytes: Array[Byte], kbytes: Array[Byte]) = {
    val key = new SecretKeySpec(kbytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key)

    cipher.doFinal(cbytes)
  }
}

