package net.logitank.cryptopals

object Base64Util {
  
  private val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

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

  private def fromIndices(abcd: Array[Byte]) = {
    val Array(a,b,c,d) = abcd
    val n = (a << 18) + (b << 12) + (c << 6) + d

    List(
      (n >>> 16) & 255,
      (n >>> 8) & 255,
      n & 255
    )
  }

  def encode(bytes: Array[Byte]) = {
    val pad = "=" * ((3 - bytes.length % 3) % 3)
    val bs = bytes.padTo(bytes.length + pad.length, 0.toByte)
    val result = bs.grouped(3).flatMap(x => toIndices(x).map(alphabet.charAt(_))).mkString

    result.slice(0, result.length - pad.length) + pad
  }

  def encode(input: String): String = encode(input.getBytes)
}
