package net.logitank.cryptopals

object Padding {

  implicit class StringPadding(val s: String) {
    def pkcs7(n: Int): String = {
      s.length % n match {
        case 0 => s
        case r =>
          val m = n - r
          s + ("" + m.toChar) * m
      }
    }
  }

  implicit class ArrayPadding(val as: Array[Byte]) {
    def pkcs7(n: Int): Array[Byte] = {
      as.length % n match {
        case 0 => as
        case r =>
          val m = n - r
          as ++ Array.fill[Byte](m)(m.toByte)
      }
    }
  }
}
