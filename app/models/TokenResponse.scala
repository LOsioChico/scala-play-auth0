package models

import play.api.libs.json.{ Json, OFormat }

case class TokenResponse(
  access_token: String,
  refresh_token: Option[String],
  id_token: Option[String],
  token_type: String,
  expires_in: Int
)

object TokenResponse:
  implicit val format: OFormat[TokenResponse] = Json.format[TokenResponse]
