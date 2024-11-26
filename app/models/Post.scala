package models

import play.api.libs.json.{ Json, OFormat }

case class Post(id: Int, content: String)

object Post:
  implicit val format: OFormat[Post] = Json.format[Post]
