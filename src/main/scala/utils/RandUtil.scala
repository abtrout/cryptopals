package net.logitank.cryptopals.RandUtil

// Mersenne Twister PRNG (MT19937)
// <https://en.wikipedia.org/wiki/Mersenne_Twister>
class MT19937(seed: Int = 5289, initialState: Option[Array[Int]] = None) {

  import net.logitank.cryptopals.XORUtil

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
  private val mt = initialState.getOrElse(Array.fill[Int](n)(0))
  if(initialState.isEmpty) seedWith(seed)

  def seedWith(s: Int) = {
    index = n
    mt(0) = s
    (1 until n).foreach { i =>
      mt(i) = (f * (mt(i-1) ^ (mt(i-1) >> (w-2))) + i)
    }
  }

  def nextInt = {
    if(index >= n) twist

    var y = mt(index)
    index = index + 1
    temper(y)
  }

  def temper(x: Int): Int = {
    val y0 = x ^ ((x >>> u) & d)
    val y1 = y0 ^ ((y0 << s) & b)
    val y2 = y1 ^ ((y1 << t) & c)
    val y = y2 ^ (y2 >>> l)
    y
  }

  def untemper(y: Int): Int = {
    val y2 = XORUtil.invertRightShiftAndXOR(y, d, l)
    val y1 = XORUtil.invertLeftShiftAndXOR(y2, c, t)
    val y0 = XORUtil.invertLeftShiftAndXOR(y1, b, s)
    val x = XORUtil.invertRightShiftAndXOR(y0, d, u)
    x
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
