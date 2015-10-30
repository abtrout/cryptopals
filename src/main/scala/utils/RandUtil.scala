package net.logitank.cryptopals.RandUtil

// Mersenne Twister PRNG (MT19937)
// <https://en.wikipedia.org/wiki/Mersenne_Twister>
class MT19937(initial: Int = 5289) {

  private val (w, n, m, r) = (32, 624, 397, 31)
  private var index = n+1
  private val f = 1812433253
  private val a = 0x9908b0df
  private val (u, d) = (11, 0xffffffff)
  private val (s, b) = (7, 0x9d2c5680)
  private val (t, c) = (15, 0xefc60000)
  private val l = 18
  private val lowerMask = (1 << r) - 1
  private val upperMask = ~lowerMask

  // Initialize generator from provided seed
  private val mt = Array.fill[Int](n)(0)
  seed(initial)

  def seed(s: Int) = {
    index = n
    mt(0) = s
    (1 until n).foreach { i =>
      mt(i) = (f * (mt(i-1) ^ (mt(i-1) >> (w-2))) + i)
    }
  }

  def nextInt = {
    if(index >= n) twist

    var y = mt(index)
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    index = index + 1
    y
  }

  private def twist = {
    (0 until n).foreach { i =>
      val x = (mt(i) & upperMask) + (mt((i+1) % n) & lowerMask)
      val xA = {
        if(x % 2 != 0) (x >> 1) ^ a
        else x >> 1
      }

      mt(i) = mt((i + m) % n) ^ xA
    }

    index = 0
  }
}
