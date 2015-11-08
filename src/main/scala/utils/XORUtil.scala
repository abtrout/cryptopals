package net.logitank.cryptopals

object XORUtil {

  def fixedXOR(as: Array[Byte], bs: Array[Byte]) =
    as.zip(bs).map(ab => (ab._1 ^ ab._2).toByte)

  def singleByte(a: Byte, bs: Array[Byte]) =
    fixedXOR(Array.fill[Byte](bs.length)(a), bs)

  // Inverts y = x ^ ((x >>> n) & c)
  // Thinking of n-bit blocks from the left, y_i:
  // * y_i = x_i, 0 <= i <= n
  // * y_i = x_i ^ (x_{i-n} & c_i), i > n
  //
  // So, we can compute the first n-bit block right away,
  // and use it to calculate the rest bit-by-bit.
  def invertRightShiftAndXOR(y: Int, c: Int, n: Int) = {
    val x0 = (y ^ (y >>> n)) & (-1 << Math.max(0, 32 - n))
    (n to 31).foldLeft(x0) { (x, i) =>
      x | ((y ^ ((x >>> n) & c)) & (1 << (31 - i)))
    }
  }

  // Inverts y = x ^ ((x << n) & c). We use exactly the same strategy
  // as inverting right shift XOR, but from the opposite direction.
  def invertLeftShiftAndXOR(y: Int, c: Int, n: Int) = {
    val x0 = (y ^ (y << n)) & (-1 >>> Math.max(0, 32 - n))
    (n to 31).foldLeft(x0) { (x, i) =>
      x | ((y ^ ((x << n) & c)) & (1 << i))
    }
  }
}
