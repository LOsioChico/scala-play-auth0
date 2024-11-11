package controllers

import javax.inject.{Inject, Singleton}
import play.api.mvc.{Action, AnyContent, BaseController, ControllerComponents}
import play.api.libs.json.Json
import repositories.DataRepository
import auth.AuthAction

@Singleton
class ApiController @Inject() (
    val controllerComponents: ControllerComponents,
    val dataRepository: DataRepository,
    val authAction: AuthAction
) extends BaseController {

  def ping: Action[AnyContent] = Action { implicit request =>
    Ok("Hello, Scala!")
  }

  def getPost(postId: Int): Action[AnyContent] = authAction {
    implicit request =>
      dataRepository.getPost(postId) map { post =>
        Ok(Json.toJson(post))
      } getOrElse NotFound
  }

  def getComments(postId: Int): Action[AnyContent] = authAction {
    implicit request =>
      Ok(Json.toJson(dataRepository.getComments(postId)))
  }
}
