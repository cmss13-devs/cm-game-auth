#![forbid(unsafe_code)]

use rocket::fairing::{Fairing, Info, Kind};
use rocket::figment::value::Value;
use rocket::http::{Header, Status};
use rocket::response::content::RawHtml;
use rocket::{
    fairing::AdHoc,
    figment::{
        providers::{Format, Serialized, Toml},
        Figment,
    },
};
use rocket::{Request, Response};
use rocket_db_pools::{sqlx::MySqlPool, Database};
use serde::{Deserialize, Serialize};

#[macro_use]
extern crate rocket;

pub struct CORS;

mod auth;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ForumsOAuthConfig {
    auth_endpoint: String,
    token_endpoint: String,
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct DiscordOAuthConfig {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
#[derive(Default)]
struct Config {
    forums: Option<ForumsOAuthConfig>,
    discord: Option<DiscordOAuthConfig>,
    base_url: String
}

#[derive(Database)]
#[database("cmdb")]
pub struct Cmdb(MySqlPool);

#[launch]
fn rocket() -> _ {
    let figment = Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(Config::default()))
        .merge(Toml::file("Rocket.toml").nested())
        .merge(Toml::file("Api.toml"));

    let base_url: String = match figment.find_value("host.base_url") {
        Ok(value) => match value {
            Value::String(_, val) => val,
            _ => panic!("base_url must be a string."),
        },
        Err(_) => "/".to_string(),
    };

    rocket::custom(figment)
        .attach(Cmdb::init())
        .attach(AdHoc::config::<Config>())
        .attach(CORS)
        .mount(
            format!("{}/forums", base_url),
            routes![auth::forums_authenticate, auth::forums_callback],
        )
        .mount(
            format!("{}/discord", base_url),
            routes![auth::discord_authenticate, auth::discord_callback],
        )
        .register("/", catchers![default])
}

pub fn get_response_html(response_message: &str) -> RawHtml<String> {
    RawHtml(
    "<!DOCTYPE html>
    <html>

    <head>
        <style>
            .main {
                background-image: none;
                background: radial-gradient(rgba(0, 235, 78, 0.2),
                        rgba(0, 235, 78, 0.04));
                width: 100vw;
                height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
            }

            .main::after {
                content: ' ';
                display: block;
                position: absolute;
                top: 0;
                left: 0;
                bottom: 0;
                right: 0;
                background: hsla(0, 6%, 7%, 0.1);
                opacity: 0;
                z-index: 2;
                pointer-events: none;
            }

            .main::before {
                content: ' ';
                display: block;
                position: absolute;
                top: 0;
                left: 0;
                bottom: 0;
                right: 0;
                background: linear-gradient(hsla(0, 6%, 7%, 0) 50%,
                        hsla(0, 0%, 0%, 0.25) 50%),
                    linear-gradient(90deg,
                        hsla(0, 100%, 50%, 0.06),
                        hsla(120, 100%, 50%, 0.02),
                        hsla(240, 100%, 50%, 0.06));
                z-index: 2;
                background-size: 100% 2px, 3px 100%;
                pointer-events: none;
            }

            body {
                background-color: #1a1919;
                margin: 0px;
                font-family: monospace;
                color: white;
            }

            .text {
                text-align: center;
                font-size: 18px;
            }
        </style>
    </head>

    <body>
        <div class='main'><div class='text'>(%PLACEHOLDER$)</div></div>
    </body>

    </html>
    ".replace("(%PLACEHOLDER$)", response_message))
}

#[catch(default)]
fn default(status: Status, _req: &Request) -> RawHtml<String> {
    if let Some(reason) = status.reason() {
        return get_response_html(format!("{}: {}", status.code, reason).as_str())
    }

    get_response_html(format!("{}", status.code).as_str())
}