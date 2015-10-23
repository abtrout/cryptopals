package net.logitank.cryptopals

object Hamming {

  private def bitsum(b: Int) = (0 to 7).map(i => (b >> i) & 1).sum

  def distance(as: Array[Byte], bs: Array[Byte]) = {
    as.zip(bs).map(ab => bitsum(ab._1 ^ ab._2)).sum
  }

  def distance(s1: String, s2: String): Int = {
    val as = s1.toCharArray.map(_.toByte)
    val bs = s2.toCharArray.map(_.toByte)

    distance(as, bs)
  }
}
