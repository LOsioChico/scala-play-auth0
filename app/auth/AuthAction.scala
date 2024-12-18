package auth

import scala.concurrent.{ ExecutionContext, Future }
import scala.util.{ Failure, Success }

import javax.inject.Inject
import pdi.jwt.{ JwtClaim, JwtJson }
import play.api.mvc.{ ActionBuilder, AnyContent, BodyParser, BodyParsers, Request, Result, Results, WrappedRequest }

case class UserRequest[A](
  jwt: JwtClaim,
  token: String,
  request: Request[A]
) extends WrappedRequest[A](request)

class AuthAction @Inject() (
  bodyParser: BodyParsers.Default,
  authService: AuthService
)(implicit ec: ExecutionContext)
  extends ActionBuilder[UserRequest, AnyContent]:

  override def parser: BodyParser[AnyContent]               = bodyParser
  override protected def executionContext: ExecutionContext = ec

  override def invokeBlock[A](
    request: Request[A],
    block: UserRequest[A] => Future[Result]
  ): Future[Result] =
    request.session.get("access_token") match
      case Some(token) =>
        authService
          .validateJwt(token)
          .flatMap:
            case Success(claim) => block(UserRequest(claim, token, request))
            case Failure(t)     => Future.successful(Results.Unauthorized(t.getMessage))
      case None =>
        Future.successful(Results.Unauthorized)
