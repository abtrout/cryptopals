package net.logitank.cryptopals

object Padding {

  implicit class ArrayPadding(val bytes: Array[Byte]) {
    def padPKCS7(n: Int): Array[Byte] = {
      val length = n - (bytes.length % n)
      bytes ++ Array.fill[Byte](length)(length.toByte)
    }

    def unpadPKCS7: Array[Byte] = {
      val padStart = bytes.length - bytes.last.toInt
      val slice = bytes.slice(padStart, bytes.length).toList

      slice.toList.distinct match {
        case List(_) => bytes.slice(0, padStart)
        case xs => throw new Exception("Invalid PKCS#7 padding")
      }
    }
  }
}
