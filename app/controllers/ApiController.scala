package controllers

import javax.inject.{Inject, Singleton}
import play.api.mvc.{Action, AnyContent, BaseController, ControllerComponents}
import play.api.libs.json.Json
import repositories.DataRepository

@Singleton
class ApiController @Inject()(val controllerComponents: ControllerComponents,
                              dataRepository: DataRepository)
  extends BaseController {

  def ping: Action[AnyContent] = Action { implicit request =>
    Ok("Hello, Scala!")
  }
  
  def getPost(postId: Int): Action[AnyContent] = Action { implicit request =>
    dataRepository.getPost(postId) map { post =>
      Ok(Json.toJson(post))
    } getOrElse NotFound
  }

  def getComments(postId: Int): Action[AnyContent] = Action { implicit request =>
    Ok(Json.toJson(dataRepository.getComments(postId)))
  }
}