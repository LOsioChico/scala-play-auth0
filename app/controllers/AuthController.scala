package controllers

import scala.concurrent.{ ExecutionContext, Future }
import scala.util.{ Failure, Success }

import javax.inject.Inject
import play.api.Configuration
import play.api.libs.json.Json
import play.api.mvc.{ Action, AnyContent, BaseController, ControllerComponents }

import auth.AuthService
import models.{ TokenResponse, UserInfo }

class AuthController @Inject() (
  val controllerComponents: ControllerComponents,
  authService: AuthService,
  config: Configuration
)(implicit ec: ExecutionContext)
  extends BaseController:

  private val domain      = config.get[String]("auth0.domain")
  private val clientId    = config.get[String]("auth0.clientId")
  private val redirectUri = config.get[String]("auth0.redirectUri")
  private val audience    = config.get[String]("auth0.audience")

  def login(): Action[AnyContent] = Action {
    implicit request =>
      request.session.get("access_token") match
        case Some(_) => Redirect(routes.ApiController.home())
        case None    => Ok(views.html.auth.login())
  }

  def handleLogin(): Action[AnyContent] = Action.async {
    implicit request =>
      val jsonBody = Json.parse(request.body.asText.getOrElse(""))

      val loginRequest = for
        email    <- (jsonBody \ "email").asOpt[String]
        password <- (jsonBody \ "password").asOpt[String]
      yield authService
        .loginWithPassword(email, password)
        .flatMap:
          case Left(result) =>
            Future.successful(Unauthorized(Json.toJson(result)))
          case Right(tokenResponse) =>
            authService
              .getUserInfo(tokenResponse.access_token)
              .map: userInfo =>
                val session = Map(
                  "access_token"  -> tokenResponse.access_token,
                  "refresh_token" -> tokenResponse.refresh_token.getOrElse(""),
                  "id_token"      -> tokenResponse.id_token.getOrElse(""),
                  "user_info"     -> Json.toJson(userInfo).toString()
                )
                Redirect(routes.ApiController.home())
                  .withSession(session.toSeq*)

      loginRequest
        .getOrElse(Future.successful(BadRequest("Invalid request body")))
  }

  def callback(code: Option[String], state: Option[String]): Action[AnyContent] =
    Action.async {
      code match
        case Some(authCode) =>
          authService
            .getAuthorizationCodeToken(authCode)
            .map:
              case Some(_) => Ok("Token received")
              case None    => Unauthorized("Failed to get token")
        case None =>
          Future.successful(BadRequest("No code provided"))
    }

  def logout(): Action[AnyContent] = Action {
    val logoutUrl = s"https://$domain/v2/logout" +
      s"?client_id=$clientId" +
      s"&returnTo=${config.get[String]("auth0.postLogoutRedirectUri")}"

    Redirect(logoutUrl).withNewSession
  }

  def resetPassword(): Action[AnyContent] = Action {
    implicit request =>
      Ok(views.html.auth.resetPassword())
  }

  def handleResetPassword(): Action[AnyContent] = Action.async {
    implicit request =>
      val jsonBody = Json.parse(request.body.asText.getOrElse(""))
      val email    = (jsonBody \ "email").asOpt[String]
      email match
        case Some(email) =>
          authService.resetPassword(email).map {
            case Right(message) => Ok(message)
            case Left(error)    => BadRequest(error)
          }
        case None =>
          Future.successful(BadRequest("Email is required"))
  }
