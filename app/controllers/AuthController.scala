package controllers

import javax.inject.{Inject, Singleton}
import play.api.mvc.{
  AbstractController,
  Action,
  AnyContent,
  ControllerComponents
}
import play.api.Configuration
import auth.AuthService
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class AuthController @Inject() (
    cc: ControllerComponents,
    config: Configuration,
    authService: AuthService
)(implicit ec: ExecutionContext)
    extends AbstractController(cc) {

  private val domain = config.get[String]("auth0.domain")
  private val clientId = config.get[String]("auth0.clientid")
  private val audience = config.get[String]("auth0.audience")

  def home: Action[AnyContent] = Action { implicit request =>
    Ok(views.html.home(domain, clientId))
  }

  def login: Action[AnyContent] = Action { implicit request =>
    Ok(views.html.auth.login(domain, clientId))
  }

  def callback: Action[AnyContent] = Action.async { implicit request =>
    request.getQueryString("code") match {
      case Some(code) =>
        Future.successful(Redirect("/").withSession("auth_code" -> code))
      case None =>
        Future.successful(
          Redirect("/login").flashing("error" -> "No authorization code found")
        )
    }
  }
}
