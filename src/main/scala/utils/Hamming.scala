package net.logitank.cryptopals

object Hamming {

  private def bitsum(b: Int) = (0 to 7).map(i => (b >> i) & 1).sum

  def distance(as: Array[Byte], bs: Array[Byte]) = {
    as.zip(bs).map(ab => bitsum(ab._1 ^ ab._2)).sum
  }
  
  // for convenience:
  def distance(s1: String, s2: String): Int = distance(s1.getBytes, s2.getBytes)
}
