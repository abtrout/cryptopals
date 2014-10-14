package net.logitank.cryptopals

object Base64Util {
  
  private val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  private val alphabytes = alphabet.getBytes

  private def toIndices(abc: Array[Byte]) = {
    val Array(a,b,c) = abc
    val n = (a << 16) + (b << 8) + c

    List(
      (n >>> 18) & 63,
      (n >>> 12) & 63,
      (n >>> 6) & 63,
      n & 63
    )
  }

  def encode(bytes: Array[Byte]) = {
    val pad = "=" * ((3 - bytes.length % 3) % 3)
    val bs = bytes.padTo(bytes.length + pad.length, 0.toByte)
    val result = bs.grouped(3).flatMap(x => toIndices(x).map(alphabet.charAt(_))).mkString

    result.slice(0, result.length - pad.length) + pad
  }

  def encode(input: String): String = encode(input.getBytes)

  private def fromIndices(abcd: Array[Byte]) = {
    val Array(a,b,c,d) = abcd.map(alphabytes.indexOf(_))
    val n = (a << 18) + (b << 12) + (c << 6) + d

    List(
      (n >>> 16) & 255,
      (n >>> 8) & 255,
      n & 255
    )
  }

  def decode(bytes: Array[Byte]) = {
    val padding = bytes.reverse.indexWhere(_ != '='.toByte)
    val numBytes = bytes.length - padding

    val bs = bytes.slice(0, numBytes).padTo(numBytes + padding, 'A'.toByte)
    val result = bs.grouped(4).flatMap(x => fromIndices(x).map(_.toChar)).mkString

    result.slice(0, result.length - padding)
  }

  def decode(input: String): String = {
    val stripped = s"[^${alphabet}=]".r.replaceAllIn(input, "")
    decode(stripped.getBytes)
  } 
}
