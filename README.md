# Scala Play Auth0

A web application built with Play Framework and Scala 3, featuring Auth0 integration for authentication.

## Prerequisites

- JDK 17 or higher
- sbt 1.x.x
- Scala 3.x.x

## Notes

- This application is configured to use the Auth0 sandbox environment.
- The `audience` claim is set to `scala-play-auth0.example.com` in the `application.conf` file.
- The `domain` claim is set to `dev-vnzqesbq7hcw0yfv.us.auth0.com` in the `application.conf` file.
- To get an access token, run the following curl command:

```bash
curl --request POST \
  --url https://dev-vnzqesbq7hcw0yfv.us.auth0.com/oauth/token \
  --header 'content-type: application/json' \
  --data '{"client_id":"laU2YSYku1bMeQp2JmhXSISMLZ0bzDjF","client_secret":"KagL9EAGIas5suRCQJRDhokbnTP54WI1W1v9223cj_VxdQSp6m83AogZwTko4fgV","audience":"https://scala-play-auth0.example.com","grant_type":"client_credentials"}'
```

response example:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkZPdHJ6NTFBdW5OZ0s2OVl4d190VCJ9.eyJpc3MiOiJodHRwczovL2Rldi12bnpxZXNicTdoY3cweWZ2LnVzLmF1dGgwLmNvbS8iLCJzdWIiOiJsYVUyWVNZa3UxYk1lUXAySm1oWFNJU01MWjBiekRqRkBjbGllbnRzIiwiYXVkIjoiaHR0cHM6Ly9zY2FsYS1wbGF5LWF1dGgwLmV4YW1wbGUuY29tIiwiaWF0IjoxNzMxMzQ2MDU1LCJleHAiOjE3MzE0MzI0NTUsImd0eSI6ImNsaWVudC1jcmVkZW50aWFscyIsImF6cCI6ImxhVTJZU1lrdTFiTWVRcDJKbWhYU0lTTUxaMGJ6RGpGIn0.EciZ8ZZZwcroxFH0KMvv8f5I15sEgPXYO9dTitTG4xat0wj3tLyni9GxCe_R2G14u5ggdOtTh7QFvhzcjXr0iaTupc0XHKlpIIe4NB1WQ9g7eVI7IHmevoWZZShEYlYybEB3-2gTEbGTIQKgisVd8ZKkqruu5RyO-LvcZZ_nWLtc-3zu0tSjc4knjBxfk6r0i15a9Wk63J_g-wTaOgQlbtYnT_F6ZhV1ozPucg4PBU8mPoJNyWVVGwVJ5761lWLsyoLTgnTBGSAexybPWx-WRpVbfNqjQ1xi-yC5o_btgYHRUtgkP1sfSGNilnn-AE0B-4JaRcK40SYJf6RtMGYEWw",
  "token_type": "Bearer"
}
```

## Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/losiochico/scala-play-auth0.git
   ```

2. Configure the application:

   - Set the `AUTH0_DOMAIN` and `AUTH0_AUDIENCE` environment variables to the values you obtained from the Auth0 application settings.

3. Run the application:

   ```bash
   sbt compile
   sbt run 9000
   ```
