package net.logitank.cryptopals

object Base64Util {
  
  private val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

  private def computeIndices(abc: Array[Byte]) = {
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
    val pad = (3 - bytes.length % 3) % 3
    val indices = bytes.padTo(pad, 0.toByte).grouped(3).map(computeIndices(_)).flatten
    indices.map(alphabet.charAt(_)).mkString
  }

  def encode(input: String): String = encode(input.getBytes)
}
