use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use rand::{distr::Alphanumeric, Rng};
use rocket::{response::Redirect, State};
use rocket_db_pools::Connection;
use serde::Deserialize;
use sqlx::{prelude::FromRow, query, query_as};

use crate::{Cmdb, Config};

#[get("/authenticate?<code>")]
pub async fn forums_authenticate(code: &str, config: &State<Config>) -> Redirect {
    let oauth_config = config.forums.as_ref().unwrap();

    let nonce: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(14)
        .map(char::from)
        .collect();

    Redirect::found(format!("{}?scope=openid%20profile&response_type=code&client_id={}&redirect_uri={}/forums/callback&nonce={}&state={}", &oauth_config.auth_endpoint, &oauth_config.client_id, &config.base_url, &nonce, code))
}

#[get("/authenticate?<code>")]
pub async fn discord_authenticate(code: &str, config: &State<Config>) -> Redirect {
    let oauth_config = config.discord.as_ref().unwrap();

    Redirect::found(format!("https://discord.com/oauth2/authorize?scope=openid+identify&response_type=code&client_id={}&redirect_uri={}/discord/callback&state={}", &oauth_config.client_id, &config.base_url, code))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct OAuthResponse {
    access_token: String,
    expires_in: i32,
    id_token: String,
    scope: String,
    token_type: String,
    refresh_token: Option<String>
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct OAuthUser {
    iss: String,
    aud: Vec<String>,
    iat: i32,
    exp: i32,
    auth_time: i32,
    at_hash: String,
    sub: String,

    email: Option<String>,
    email_verified: Option<bool>,
    groups: Option<Vec<String>>,
    jti: Option<String>,
    name: Option<String>,
    nonce: Option<String>,
    picture: Option<String>,
    rat: Option<i32>,
}

#[get("/callback?<code>&<scope>&<state>")]
#[allow(unused_variables)]
pub async fn forums_callback(
    mut db: Connection<Cmdb>,
    code: &str,
    scope: &str,
    state: &str,
    config: &State<Config>,
) -> String {
    let oauth_config = config.forums.as_ref().unwrap();

    if !state.chars().all(char::is_alphanumeric) {
        return String::from("Invalid token.");
    };

    let http_client = reqwest::Client::new();

    let result = http_client
        .post(&oauth_config.token_endpoint)
        .form(&[
            ("client_id", &oauth_config.client_id),
            ("client_secret", &oauth_config.client_secret),
            ("grant_type", &String::from("authorization_code")),
            ("code", &code.to_string()),
            (
                "redirect_uri",
                &format!("{}/forums/callback", &config.base_url),
            ),
        ])
        .send()
        .await;

    let Ok(response) = result else {
        return String::from("No response provided from authentication server.");
    };

    let Ok(json) = response.json::<OAuthResponse>().await else {
        return String::from("Unable to parse response");
    };

    let user = match get_user_from_jwt(&json.id_token) {
        Ok(user) => user,
        Err(error) => return error,
    };

    let Ok(query) = query("UPDATE authentication_requests SET approved = 1, external_username = ? WHERE access_code = ?").bind(user.sub).bind(state).execute(&mut **db).await else {
        return String::from("An error occured interfacing with the database.")
    };

    if query.rows_affected() == 0 {
        return String::from("Your authentication request could not be found. Please try again.");
    };

    String::from("Your authentication request has been approved. You can now return to the game.")
}

#[derive(FromRow)]
struct DiscordLink {
    player_id: i32,
}

#[get("/callback?<code>&<state>")]
#[allow(unused_variables)]
pub async fn discord_callback(
    mut db: Connection<Cmdb>,
    code: &str,
    state: &str,
    config: &State<Config>,
) -> String {
    let oauth_config = config.discord.as_ref().unwrap();

    if !state.chars().all(char::is_alphanumeric) {
        return String::from("Invalid token.");
    };

    let http_client = reqwest::Client::new();

    let result = http_client
        .post("https://discord.com/api/v10/oauth2/token")
        .basic_auth(&oauth_config.client_id, Some(&oauth_config.client_secret))
        .form(&[
            ("grant_type", &String::from("authorization_code")),
            ("code", &code.to_string()),
            (
                "redirect_uri",
                &format!("{}/discord/callback", &config.base_url),
            ),
        ])
        .send()
        .await;

    let Ok(response) = result else {
        return String::from("No response provided from authentication server.");
    };

    let json = match response.json::<OAuthResponse>().await {
        Ok(json) => json,
        Err(error) => return format!("Unable to parse response: {}", error),
    };



    let user = match get_user_from_jwt(&json.id_token) {
        Ok(user) => user,
        Err(error) => return error,
    };

    let db = &mut **db;

    let Ok(discord_query): Result<DiscordLink, sqlx::Error> = query_as("SELECT player_id FROM discord_links WHERE discord_id = ?").bind(&user.sub).fetch_one(&mut *db).await else {
        return String::from("In order to use Discord authentication, you must have previously linked your CKEY in game.")
    };

    let Ok(query) = query("UPDATE authentication_requests SET approved = 1, internal_user_id = ? WHERE access_code = ?").bind(discord_query.player_id).bind(state).execute(&mut *db).await else {
        return String::from("An error occured interfacing with the database.")
    };

    if query.rows_affected() == 0 {
        return String::from("Your authentication request could not be found. Please try again.");
    };

    String::from("Your authentication request has been approved. You can now return to the game.")
}

fn get_user_from_jwt(jwt: &str) -> Result<OAuthUser, String> {
    let Some(user) = jwt.split('.').nth(1) else {
        return Err(String::from("Could not retrieve user from response."));
    };

    let Ok(decoded_user) = BASE64_STANDARD_NO_PAD.decode(user) else {
        return Err(String::from("Could not decode user from response."));
    };

    let Ok(parsed_user) = String::from_utf8(decoded_user) else {
        return Err(String::from("An error occured"));
    };

    let Ok(json_user) = serde_json::from_str::<OAuthUser>(&parsed_user) else {
        return Err(String::from("Unable to parse user from response."));
    };

    Ok(json_user)
}