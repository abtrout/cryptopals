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
