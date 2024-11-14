package controllers

import javax.inject.Inject
import play.api.mvc._
import play.api.Configuration
import auth.AuthService
import scala.concurrent.{ExecutionContext, Future}
import views.html.home
import scala.util.{Success, Failure}
import play.api.data.Form
import play.api.data.Forms._
import play.api.libs.json.Json
import models._

class AuthController @Inject() (
    val controllerComponents: ControllerComponents,
    authService: AuthService,
    config: Configuration
)(implicit ec: ExecutionContext)
    extends BaseController {

  private val domain = config.get[String]("auth0.domain")
  private val clientId = config.get[String]("auth0.clientId")
  private val redirectUri = config.get[String]("auth0.redirectUri")
  private val audience = config.get[String]("auth0.audience")

  def login(): Action[AnyContent] = Action { implicit request =>
    request.session.get("access_token") match {
      case Some(_) => Redirect(routes.ApiController.home())
      case None    => Ok(views.html.auth.login())
    }
  }

  def handleLogin(): Action[AnyContent] = Action.async { implicit request =>
    val jsonBody = Json.parse(request.body.asText.getOrElse(""))

    val loginRequest = for {
      email <- (jsonBody \ "email").asOpt[String]
      password <- (jsonBody \ "password").asOpt[String]
    } yield authService.loginWithPassword(email, password).flatMap {
      case Right(tokenResponse) =>
        authService.getUserInfo(tokenResponse.access_token).map { userInfo =>
          val session = Map(
            "access_token" -> tokenResponse.access_token,
            "refresh_token" -> tokenResponse.refresh_token.getOrElse(""),
            "id_token" -> tokenResponse.id_token.getOrElse(""),
            "user_info" -> Json.toJson(userInfo).toString()
          )
          Redirect(routes.ApiController.home())
            .withSession(session.toSeq: _*)
        }
      case Left(result) =>
        Future.successful(Unauthorized(result))
    }

    loginRequest.getOrElse(
      Future.successful(BadRequest("Invalid request body"))
    )
  }

  def callback(code: Option[String], state: Option[String]) = Action.async {
    implicit request =>
      code match {
        case Some(authCode) =>
          authService.getAuthorizationCodeToken(authCode).flatMap {
            case Some(tokenResponse) =>
              Future.successful(Ok("Token received"))
            case None =>
              Future.successful(Unauthorized("Failed to get token"))
          }
        case None =>
          Future.successful(BadRequest("No code provided"))
      }
  }

  def logout() = Action {
    val logoutUrl = s"https://$domain/v2/logout" +
      s"?client_id=$clientId" +
      s"&returnTo=${config.get[String]("auth0.postLogoutRedirectUri")}"

    Redirect(logoutUrl).withNewSession
  }
}
