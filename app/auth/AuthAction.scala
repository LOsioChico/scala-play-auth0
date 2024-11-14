package auth

import javax.inject.Inject
import pdi.jwt._
import play.api.http.HeaderNames
import play.api.mvc._

import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Success}

case class UserRequest[A](jwt: JwtClaim, token: String, request: Request[A])
    extends WrappedRequest[A](request)

class AuthAction @Inject() (
    bodyParser: BodyParsers.Default,
    authService: AuthService
)(implicit ec: ExecutionContext)
    extends ActionBuilder[UserRequest, AnyContent] {

  override def parser: BodyParser[AnyContent] = bodyParser
  override protected def executionContext: ExecutionContext = ec

  private val headerTokenRegex = """(?i)bearer (.+?)""".r

  override def invokeBlock[A](
      request: Request[A],
      block: UserRequest[A] => Future[Result]
  ): Future[Result] =
    extractBearerToken(request) match {
      case Some(token) =>
        authService.validateJwt(token).flatMap {
          case Success(claim) => block(UserRequest(claim, token, request))
          case Failure(t) =>
            Future.successful(Results.Unauthorized(t.getMessage))
        }
      case None =>
        Future.successful(Results.Unauthorized)

    }

  private def extractBearerToken[A](request: Request[A]): Option[String] =
    request.headers.get(HeaderNames.AUTHORIZATION) collect {
      case headerTokenRegex(token) => token
    }
}
