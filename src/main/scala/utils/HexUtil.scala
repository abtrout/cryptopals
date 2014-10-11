package net.logitank.cryptopals

object HexUtil {

  def toBytes(hex: String) = {
    hex.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
  }

  def fromBytes(bytes: Array[Byte]) = {
    // adding .toLowerCase since most of matasano's answers are lowercase...
    bytes.map(b => String.format("%02X", java.lang.Byte.valueOf(b))).mkString.toLowerCase
  }
}
