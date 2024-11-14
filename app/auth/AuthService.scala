package auth

import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Success, Try}

import javax.inject.Inject

import pdi.jwt._
import play.api.Configuration
import play.api.libs.json._
import play.api.libs.ws.WSClient
import play.api.mvc.Results.Unauthorized
import play.api.http.HeaderNames

import play.api.libs.ws.WSBodyWritables.writeableOf_urlEncodedForm
import play.api.mvc.Session
import play.api.mvc.Result

case class TokenResponse(
    access_token: String,
    refresh_token: Option[String],
    id_token: Option[String],
    token_type: String,
    expires_in: Int
)
class AuthService @Inject() (
    config: Configuration,
    ws: WSClient
)(implicit ec: ExecutionContext) {

  private val jwtRegex = """(.+?)\.(.+?)\.(.+?)""".r

  private val clientId = config.get[String]("auth0.clientId")
  private val clientSecret = config.get[String]("auth0.clientSecret")
  private val domain = config.get[String]("auth0.domain")
  private val audience = config.get[String]("auth0.audience")
  private val redirectUri = config.get[String]("auth0.redirectUri")

  private val issuer = s"https://$domain/"
  private val jwksUrl = s"https://$domain/.well-known/jwks.json"
  private val tokenUrl = s"https://$domain/oauth/token"
  private val userInfoUrl = s"https://$domain/userinfo"

  // Validates a JWT and potentially returns the claims if the token was
  // successfully parsed and validated
  def validateJwt(token: String): Future[Try[JwtClaim]] = {
    fetchJwks().map { jwks =>
      for {
        jwk <- getJwk(token, jwks)
        publicKey <- createPublicKey(jwk)
        claims <- JwtJson.decode(token, publicKey, Seq(JwtAlgorithm.RS256))
        _ <- validateClaims(claims)
      } yield claims
    }
  }

  private def createPublicKey(jwk: Jwk): Try[java.security.PublicKey] = Try {
    val decoder = java.util.Base64.getUrlDecoder
    val modulus = java.math.BigInteger(1, decoder.decode(jwk.n))
    val exponent = java.math.BigInteger(1, decoder.decode(jwk.e))
    val keySpec = new java.security.spec.RSAPublicKeySpec(modulus, exponent)
    java.security.KeyFactory.getInstance("RSA").generatePublic(keySpec)
  }

  private val splitToken = (jwt: String) =>
    jwt match {
      case jwtRegex(header, body, sig) => Success((header, body, sig))
      case _ =>
        Failure(new Exception("Token does not match the correct pattern"))
    }

  private val decodeElements = (data: Try[(String, String, String)]) =>
    data map { case (header, body, sig) =>
      (JwtBase64.decodeString(header), JwtBase64.decodeString(body), sig)
    }

  private case class Jwk(kid: String, n: String, e: String)
  private implicit val jwkReads: Reads[Jwk] = Json.reads[Jwk]

  private def fetchJwks(): Future[Seq[Jwk]] = {
    ws.url(jwksUrl)
      .get()
      .map(response => (response.json \ "keys").as[Seq[Jwk]])
  }

  // Gets the JWK from the JWKS endpoint
  private def getJwk(token: String, jwks: Seq[Jwk]): Try[Jwk] =
    (splitToken andThen decodeElements)(token) flatMap { case (header, _, _) =>
      val jwtHeader = JwtJson.parseHeader(header)
      jwtHeader.keyId match {
        case Some(kid) =>
          jwks
            .find(_.kid == kid)
            .map(Success(_))
            .getOrElse(
              Failure(new Exception(s"Unable to find JWK for kid: $kid"))
            )
        case None =>
          Failure(new Exception("Unable to retrieve kid from token header"))
      }
    }

  // Validates the claims inside the token. 'isValid' checks the issuedAt, expiresAt,
  // issuer and audience fields.
  private val validateClaims = (claims: JwtClaim) => {
    val audienceValid = claims.audience.exists(_.contains(audience))
    if (
      claims.isValid(issuer)(using java.time.Clock.systemUTC) && audienceValid
    )
    then Success(claims)
    else Failure(new Exception("The JWT did not pass validation"))
  }

  // Client Credentials Flow
  def getClientCredentialsToken(): Future[Option[String]] = {
    val tokenRequest = ws
      .url(tokenUrl)
      .withHttpHeaders(
        HeaderNames.CONTENT_TYPE -> "application/x-www-form-urlencoded"
      )
      .post(
        Map(
          "grant_type" -> Seq("client_credentials"),
          "client_id" -> Seq(clientId),
          "client_secret" -> Seq(clientSecret),
          "audience" -> Seq(audience)
        )
      )

    tokenRequest.map { response =>
      (response.json \ "access_token").asOpt[String]
    }
  }

  // Authorization Code Flow
  def getAuthorizationCodeToken(code: String): Future[Option[TokenResponse]] = {
    val tokenRequest = ws
      .url(tokenUrl)
      .withHttpHeaders(
        HeaderNames.CONTENT_TYPE -> "application/x-www-form-urlencoded"
      )
      .post(
        Map(
          "grant_type" -> Seq("authorization_code"),
          "client_id" -> Seq(clientId),
          "client_secret" -> Seq(clientSecret),
          "code" -> Seq(code),
          "redirect_uri" -> Seq(redirectUri)
        )
      )

    tokenRequest
      .map { response =>
        response.status match {
          case 200 => Some(response.json.as[TokenResponse])
          case _ =>
            println(s"Auth0 error: ${response.json}")
            None
        }
      }
      .recover { case e: Exception =>
        println(s"Token request failed: ${e.getMessage}")
        None
      }
  }

  def getUserInfo(accessToken: String): Future[Option[JsValue]] = {
    ws.url(userInfoUrl)
      .withHttpHeaders(HeaderNames.AUTHORIZATION -> s"Bearer $accessToken")
      .get()
      .map { response =>
        response.status match {
          case 200 => Some(response.json)
          case _   => None
        }
      }
  }

  implicit val tokenResponseReads: Reads[TokenResponse] =
    Json.reads[TokenResponse]

  def validateSession(session: Session): Future[Boolean] = {
    session.get("access_token") match {
      case Some(token) =>
        validateJwt(token).map(_.isSuccess)
      case None => Future.successful(false)
    }
  }

  def loginWithPassword(
      email: String,
      password: String
  ): Future[Either[String, TokenResponse]] = {
    val tokenRequest = ws
      .url(tokenUrl)
      .withHttpHeaders(
        HeaderNames.CONTENT_TYPE -> "application/x-www-form-urlencoded"
      )
      .post(
        Map(
          "grant_type" -> Seq("password"),
          "username" -> Seq(email),
          "password" -> Seq(password),
          "client_id" -> Seq(clientId),
          "client_secret" -> Seq(clientSecret),
          "audience" -> Seq(audience),
          "scope" -> Seq("openid profile email offline_access")
        )
      )

    tokenRequest
      .map { response =>
        response.status match {
          case 200 => Right(response.json.as[TokenResponse])
          case _ =>
            Left((response.json \ "error_description").as[String])
        }
      }
      .recover { case e: Exception =>
        Left(e.getMessage)
      }
  }
}
