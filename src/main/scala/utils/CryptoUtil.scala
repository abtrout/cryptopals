package net.logitank.cryptopals.CryptoUtil


object Padding {
  implicit class StringPadding(val s: String) {
    // PKCS#7 <http://tools.ietf.org/html/rfc5652#section-6.3>
    def pkcs7(n: Int): String =
      (n - s.length) match {
        case k: Int if k > 0 => s.padTo(n, k.toChar)
        case k: Int if k == 0 => s
        case _ => throw new IllegalArgumentException
      }
  }
}

object AES {

  // NB: This implements AES-128 ECB, which is bad crypto. Don't use it!
  // This is for a cryptopals (http://cryptopals.com) challenge.

  import javax.crypto.Cipher
  import javax.crypto.spec.SecretKeySpec

  def encrypt(pbytes: Array[Byte], kbytes: Array[Byte]) = {
    val key = new SecretKeySpec(kbytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key)

    cipher.doFinal(pbytes)
  }

  def decrypt(cbytes: Array[Byte], kbytes: Array[Byte]) = {
    val key = new SecretKeySpec(kbytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, key)

    cipher.doFinal(cbytes)
  }

  def encrypt(plaintext: String, key: String): String =
    // note: .map(_.toByte) vs .getBytes important here in case
    // our ciphertext/plaintext contains UTF8 characters, it seems
    encrypt(plaintext.map(_.toByte).toArray, key.getBytes).map(_.toChar).mkString

  def decrypt(ciphertext: String, key: String): String =
    decrypt(ciphertext.map(_.toByte).toArray, key.getBytes).map(_.toChar).mkString
}
