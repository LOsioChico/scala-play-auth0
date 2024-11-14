package auth

import scala.concurrent.{ ExecutionContext, Future }
import scala.util.{ Failure, Success, Try }

import javax.inject.Inject
import pdi.jwt._
import play.api.Configuration
import play.api.http.HeaderNames
import play.api.libs.json.Json
import play.api.libs.ws.WSClient
import play.api.libs.ws.WSBodyWritables.writeableOf_urlEncodedForm
import play.api.mvc.Session

import models._

class AuthService @Inject() (
  config: Configuration,
  ws: WSClient
)(implicit ec: ExecutionContext) {

  private val jwtRegex = """(.+?)\.(.+?)\.(.+?)""".r

  private val clientId     = config.get[String]("auth0.clientId")
  private val clientSecret = config.get[String]("auth0.clientSecret")
  private val domain       = config.get[String]("auth0.domain")
  private val audience     = config.get[String]("auth0.audience")
  private val redirectUri  = config.get[String]("auth0.redirectUri")

  private val issuer      = s"https://$domain/"
  private val jwksUrl     = s"https://$domain/.well-known/jwks.json"
  private val tokenUrl    = s"https://$domain/oauth/token"
  private val userInfoUrl = s"https://$domain/userinfo"

  def getAuthorizationCodeToken(code: String): Future[Option[TokenResponse]] = {
    val body = Map(
      "grant_type"    -> Seq("authorization_code"),
      "client_id"     -> Seq(clientId),
      "client_secret" -> Seq(clientSecret),
      "code"          -> Seq(code),
      "redirect_uri"  -> Seq(redirectUri)
    )

    makeAuthRequest(
      url = tokenUrl,
      method = "POST",
      headers = Seq(HeaderNames.CONTENT_TYPE -> "application/x-www-form-urlencoded"),
      body = Some(body)
    ) {
      response =>
        response.status match {
          case 200 => Some(response.json.as[TokenResponse])
          case _   => None
        }
    }.recover { case _ => None }
  }

  def loginWithPassword(
    email: String,
    password: String
  ): Future[Either[String, TokenResponse]] = {
    val body = Map(
      "grant_type"    -> Seq("password"),
      "username"      -> Seq(email),
      "password"      -> Seq(password),
      "client_id"     -> Seq(clientId),
      "client_secret" -> Seq(clientSecret),
      "audience"      -> Seq(audience),
      "scope"         -> Seq("openid profile email offline_access")
    )

    makeAuthRequest(
      url = tokenUrl,
      method = "POST",
      headers = Seq(HeaderNames.CONTENT_TYPE -> "application/x-www-form-urlencoded"),
      body = Some(body)
    ) {
      response =>
        response.status match {
          case 200 => Right(response.json.as[TokenResponse])
          case _   => Left((response.json \ "error_description").as[String])
        }
    }.recover { case e: Exception => Left(e.getMessage) }
  }

  def getUserInfo(accessToken: String): Future[Option[UserInfo]] =
    makeAuthRequest(
      url = userInfoUrl,
      headers = Seq(HeaderNames.AUTHORIZATION -> s"Bearer $accessToken")
    ) {
      response =>
        response.status match {
          case 200 => Some(response.json.as[UserInfo])
          case _   => None
        }
    }

  def validateJwt(token: String): Future[Try[JwtClaim]] =
    fetchJwks().map {
      jwks =>
        for {
          jwk       <- getJwk(token, jwks)
          publicKey <- createPublicKey(jwk)
          claims    <- JwtJson.decode(token, publicKey, Seq(JwtAlgorithm.RS256))
          _         <- validateClaims(claims)
        } yield claims
    }

  private def makeAuthRequest[T](
    url: String,
    method: String = "GET",
    headers: Seq[(String, String)] = Seq.empty,
    body: Option[Map[String, Seq[String]]] = None
  )(transform: play.api.libs.ws.WSResponse => T): Future[T] = {
    val request = ws
      .url(url)
      .withHttpHeaders(headers: _*)

    val finalRequest = method match {
      case "POST" => request.post(body.getOrElse(Map.empty))
      case _      => request.get()
    }

    finalRequest.map(transform)
  }

  private def fetchJwks(): Future[Seq[Jwk]] =
    ws.url(jwksUrl)
      .get()
      .map(response => (response.json \ "keys").as[Seq[Jwk]])

  private def getJwk(token: String, jwks: Seq[Jwk]): Try[Jwk] =
    (splitToken andThen decodeElements)(token) flatMap {
      case (header, _, _) =>
        val jwtHeader = JwtJson.parseHeader(header)
        jwtHeader.keyId match {
          case Some(kid) =>
            jwks
              .find(_.kid == kid)
              .map(Success(_))
              .getOrElse(Failure(new Exception(s"Unable to find JWK for kid: $kid")))
          case None =>
            Failure(new Exception("Unable to retrieve kid from token header"))
        }
    }

  private def createPublicKey(jwk: Jwk): Try[java.security.PublicKey] = Try {
    val decoder  = java.util.Base64.getUrlDecoder
    val modulus  = java.math.BigInteger(1, decoder.decode(jwk.n))
    val exponent = java.math.BigInteger(1, decoder.decode(jwk.e))
    val keySpec  = new java.security.spec.RSAPublicKeySpec(modulus, exponent)
    java.security.KeyFactory.getInstance("RSA").generatePublic(keySpec)
  }

  private val splitToken = (jwt: String) =>
    jwt match {
      case jwtRegex(header, body, sig) => Success((header, body, sig))
      case _ => Failure(new Exception("Token does not match the correct pattern"))
    }

  private val decodeElements = (data: Try[(String, String, String)]) =>
    data map {
      case (header, body, sig) =>
        (JwtBase64.decodeString(header), JwtBase64.decodeString(body), sig)
    }

  private val validateClaims = (claims: JwtClaim) => {
    val audienceValid = claims.audience.exists(_.contains(audience))
    if claims.isValid(issuer)(using java.time.Clock.systemUTC) && audienceValid then Success(claims)
    else Failure(new Exception("The JWT did not pass validation"))
  }
}
