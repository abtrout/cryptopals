package net.logitank.cryptopals

object Hamming {
  private def bitsum(b: Int) = (0 to 7).map(i => (b >> i) & 1).sum

  def distance(s1: String, s2: String) = {
    s1.getBytes.zip(s2.getBytes).map(b => bitsum(b._1 ^ b._2)).sum
  }
}
