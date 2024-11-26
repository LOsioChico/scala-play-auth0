package models

import play.api.libs.json.{ Json, OFormat }

case class UserInfo(
  email: String,
  email_verified: Boolean,
  name: String,
  nickname: String,
  picture: String,
  sub: String,
  updated_at: String
)

object UserInfo:
  val empty: UserInfo = UserInfo(
    email = "",
    email_verified = false,
    name = "",
    nickname = "",
    picture = "",
    sub = "",
    updated_at = ""
  )

  implicit val format: OFormat[UserInfo] = Json.format[UserInfo]
