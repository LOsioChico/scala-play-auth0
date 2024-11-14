package models

import play.api.libs.json.{ Json, OFormat }

case class Jwk(kid: String, n: String, e: String)

object Jwk {
  implicit val format: OFormat[Jwk] = Json.format[Jwk]
}
