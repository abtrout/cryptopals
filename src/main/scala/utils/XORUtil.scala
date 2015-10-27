package net.logitank.cryptopals

object XORUtil {

  def fixedXOR(as: Array[Byte], bs: Array[Byte]) =
    as.zip(bs).map(ab => (ab._1 ^ ab._2).toByte)

  def singleByte(a: Byte, bs: Array[Byte]) =
    fixedXOR(Array.fill[Byte](bs.length)(a), bs)
}
