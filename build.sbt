name := "cryptopals"

organization := "net.logitank"

version := "0.1"

scalaVersion := "2.11.2"

resolvers ++= Seq(
  "Sonatype repo" at "https://oss.sonatype.org/content/repositories/releases/",
  "Scalaz Bintray Repo"  at "http://dl.bintray.com/scalaz/releases"
)

libraryDependencies += "org.specs2" % "specs2_2.11" % "2.4.2"
