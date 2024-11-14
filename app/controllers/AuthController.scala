package controllers

import javax.inject.Inject
import play.api.mvc._
import play.api.Configuration
import auth.AuthService
import scala.concurrent.{ExecutionContext, Future}
import play.api.libs.json.Json
import views.html.home
import scala.util.{Success, Failure}
import play.api.data.Form
import play.api.data.Forms._
import play.api.libs.json.Reads

case class CreateSessionRequest(
    access_token: String,
    refresh_token: Option[String],
    id_token: Option[String]
)

case class LoginRequest(email: String, password: String)

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

  implicit val createSessionReads: Reads[CreateSessionRequest] =
    Json.reads[CreateSessionRequest]

  def login(): Action[AnyContent] = Action { implicit request =>
    request.session.get("access_token") match {
      case Some(_) => Redirect(routes.AuthController.home())
      case None    => Ok(views.html.auth.login())
    }
  }

  def handleLogin(): Action[AnyContent] = Action.async { implicit request =>
    val jsonBody = Json.parse(request.body.asText.getOrElse(""))

    val loginRequest = for {
      email <- (jsonBody \ "email").asOpt[String]
      password <- (jsonBody \ "password").asOpt[String]
    } yield authService.loginWithPassword(email, password).map {
      case Right(tokenResponse) =>
        Redirect(routes.AuthController.home())
          .withSession(
            "access_token" -> tokenResponse.access_token,
            "refresh_token" -> tokenResponse.refresh_token.getOrElse(""),
            "id_token" -> tokenResponse.id_token.getOrElse("")
          )
      case Left(result) =>
        Unauthorized(result)
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
              Future.successful(
                Redirect("/")
                  .withSession(
                    "access_token" -> tokenResponse.access_token,
                    "refresh_token" -> tokenResponse.refresh_token
                      .getOrElse(""),
                    "id_token" -> tokenResponse.id_token.getOrElse("")
                  )
              )
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

  def home: Action[AnyContent] = Action.async { implicit request =>
    request.session.get("access_token") match {
      case Some(token) =>
        authService.validateJwt(token).map {
          case Success(_) => Ok(views.html.home())
          case Failure(_) =>
            Redirect(routes.AuthController.login())
              .flashing(
                "error" -> "Your session has expired. Please sign in again."
              )
              .withNewSession
        }
      case None =>
        Future.successful(Ok(views.html.home()))
    }
  }

  def createSession() = Action.async(parse.json) { implicit request =>
    request.body
      .validate[CreateSessionRequest]
      .fold(
        errors => {
          Future.successful(
            BadRequest(Json.obj("message" -> "Invalid request format"))
          )
        },
        session => {
          authService.validateJwt(session.access_token).map {
            case Success(_) =>
              Ok("Session created")
                .withSession(
                  "access_token" -> session.access_token,
                  "refresh_token" -> session.refresh_token.getOrElse(""),
                  "id_token" -> session.id_token.getOrElse("")
                )
            case Failure(e) =>
              Unauthorized(Json.obj("message" -> "Invalid token"))
          }
        }
      )
  }
}
