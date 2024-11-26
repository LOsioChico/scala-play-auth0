name         := """scala-play-auth0"""
organization := "com.losiochico"

version := "1.0-SNAPSHOT"

lazy val root = (project in file(".")).enablePlugins(PlayScala)

scalaVersion := "3.5.0"

libraryDependencies += guice
libraryDependencies += ws
libraryDependencies += "com.github.jwt-scala" %% "jwt-play" % "10.0.1"
