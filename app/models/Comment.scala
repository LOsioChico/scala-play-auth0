package models

import play.api.libs.json.{Json, OFormat}

case class Comment(id: Int, postId: Int, text: String, authorName: String)

object Comment {
  implicit val format: OFormat[Comment] = Json.format[Comment]
}