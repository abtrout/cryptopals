// NB: This implements AES-128 ECB, which is bad crypto.
// Don't use it!
// This is for a cryptopals (http://cryptopals.com) challenge.
package net.logitank.cryptopals.CryptoUtil

object AES {

  import javax.crypto.Cipher
  import javax.crypto.spec.SecretKeySpec

  def encrypt(pbytes: Array[Byte], kbytes: Array[Byte]) = {
    val key = new SecretKeySpec(kbytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key)

    cipher.doFinal(pbytes)
  }

  def encrypt(plaintext: String, key: String): String = {
    val pbytes = plaintext.map(_.toByte).toArray
    val kbytes = key.getBytes

    encrypt(pbytes, kbytes).map(_.toChar).mkString
  }
  
  def decrypt(cbytes: Array[Byte], kbytes: Array[Byte]) = {
    val key = new SecretKeySpec(kbytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, key)

    println(kbytes.length, cbytes.length)

    cipher.doFinal(cbytes)
  }

  def decrypt(ciphertext: String, key: String): String = {
    val cbytes = ciphertext.map(_.toByte).toArray
    val kbytes = key.getBytes

    decrypt(cbytes, kbytes).map(_.toChar).mkString
  }
}
