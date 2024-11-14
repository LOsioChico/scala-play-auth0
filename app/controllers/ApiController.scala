package controllers

import javax.inject.{Inject, Singleton}
import play.api.mvc.{Action, AnyContent, BaseController, ControllerComponents}
import play.api.libs.json.Json
import repositories.DataRepository
import auth.AuthAction
import models.UserInfo

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

  def home: Action[AnyContent] = Action { implicit request =>
    request.session
      .get("user_info")
      .map { userInfoStr =>
        val userInfo = Json.parse(userInfoStr).as[UserInfo]
        Ok(views.html.home(userInfo, dataRepository.getPosts))
      }
      .getOrElse {
        Ok(views.html.home(UserInfo.empty, Seq.empty))
      }
  }

  def protectedHome: Action[AnyContent] = authAction { implicit request =>
    request.session
      .get("user_info")
      .map { userInfoStr =>
        val userInfo = Json.parse(userInfoStr).as[UserInfo]
        Ok(views.html.home(userInfo, dataRepository.getPosts))
      }
      .getOrElse {
        Ok(views.html.home(UserInfo.empty, Seq.empty))
      }
  }
}
