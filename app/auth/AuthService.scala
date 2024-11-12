package auth

import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Success, Try}

import javax.inject.Inject

import pdi.jwt._
import play.api.Configuration
import play.api.libs.json._
import play.api.libs.ws.WSClient

class AuthService @Inject() (
    config: Configuration,
    ws: WSClient
)(implicit ec: ExecutionContext) {

  private val jwtRegex = """(.+?)\.(.+?)\.(.+?)""".r

  private val domain = config.get[String]("auth0.domain")
  private val audience = config.get[String]("auth0.audience")

  private val issuer = s"https://$domain/"
  private val jwksUrl = s"https://$domain/.well-known/jwks.json"

  private val loginUrl = s"https://$domain/oauth/token"

  // Validates a JWT and potentially returns the claims if the token was
  // successfully parsed and validated
  def validateJwt(token: String): Future[Try[JwtClaim]] = {
    fetchJwks().map { jwks =>
      for {
        jwk <- getJwk(token, jwks)
        publicKey <- createPublicKey(jwk)
        claims <- JwtJson.decode(token, publicKey, Seq(JwtAlgorithm.RS256))
        // _ = println(s"Claims: $claims")
        // _ = println(s"Audience: ${claims.audience}")
        // _ = println(s"Expected audience: $audience")
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

  // Splits a JWT into it's 3 component parts
  private val splitToken = (jwt: String) =>
    jwt match {
      case jwtRegex(header, body, sig) => Success((header, body, sig))
      case _ =>
        Failure(new Exception("Token does not match the correct pattern"))
    }

  // As the header and claims data are base64-encoded, this function
  // decodes those elements
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
  private val validateClaims = (claims: JwtClaim) =>
    // TODO: Validate audience
    if (claims.isValid(issuer)(using java.time.Clock.systemUTC))
    then Success(claims)
    else Failure(new Exception("The JWT did not pass validation"))
}
