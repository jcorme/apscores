extern crate hyper;
extern crate iron;
extern crate kuchiki;
extern crate router;
extern crate url;
extern crate urlencoded;

use std::collections::HashMap;
use std::env;
use std::io::{Error, Read};

use hyper::client::RedirectPolicy;
use hyper::Client;
use hyper::client::Response;
use hyper::header::{ContentType, Cookie, CookieJar, Location, SetCookie};
use iron::{headers, Iron, IronResult, Request};
use iron::Plugin;
use iron::status::Status;
use kuchiki::traits::*;
use router::Router;
use url::percent_encoding;
use urlencoded::UrlEncodedBody;

const LOGIN_URL: &'static str = "https://account.collegeboard.org/login/authenticateUser";

fn main() {
    let mut router = Router::new();
    router.get("/", home_handler);
    router.post("/", scores_handler);

    let mut args = env::args();
    let ip = args.nth(1).unwrap() + ":3000";

    Iron::new(router).http(ip.as_str()).unwrap();
}

fn home_handler(_: &mut Request) -> IronResult<iron::Response> {
    let page_html = "
        <!DOCTYPE html>
        <html>
            <head>
                \
                     <title>AP Scores</title>
            </head>
            <body>
                \
                     <form action=\"/\" method=\"post\">
                    <input type=\"text\" \
                     name=\"username\" placeholder=\"Username\" required><br>
                    \
                     <input type=\"password\" name=\"password\" placeholder=\"Password\" \
                     required><br>
                    <input type=\"submit\" value=\"Submit\">
                \
                     </form><br><br><br><br>
                     <p>The purpose of this site is \
                     for students not on the US west coast to get their scores early. The server \
                     hosting this site is in California, which gets its scores first. <strong>No \
                     data you enter is stored/logged.</strong></p><br>
                     \
                     <div>Source code available at <a \
                     href=\"https://github.com/jac0/apscores\">https://github.\
                     com/jac0/apscores</a></div>
            </body>
        </html>
    ";

    let mut resp = iron::Response::with((Status::Ok, page_html));
    resp.headers.set(headers::ContentType("text/html; charset=utf-8".parse().unwrap()));

    Ok(resp)
}

macro_rules! get_param {
    ( $query:expr, $name:expr ) => {
        match $query.get($name) {
            Some(val) => val.first().unwrap(),
            None => {
                return Ok(iron::Response::with((Status::UnprocessableEntity,
                                                format!("No {} provided.", $name))));
            }
        }
    };
}

fn scores_handler(req: &mut Request) -> IronResult<iron::Response> {
    let query = match req.get::<UrlEncodedBody>() {
        Ok(q) => q,
        Err(_) => {
            return Ok(iron::Response::with((Status::UnprocessableEntity,
                                            "Invalid body received.")));
        }
    };
    let username = get_param!(query, "username");
    let password = get_param!(query, "password");

    let text_only = query.get("t").is_some();

    match get_raw_score_page((username, password)) {
        Ok(score_page) => {
            match parse_scores(score_page) {
                Ok(scores) => {
                    let mut resp_buffer = String::new();

                    for (year, year_scores) in scores {
                        let mut local_buffer = String::new();
                        
                        if text_only {
                            local_buffer.push_str(&format!("{}\n", year));
                        } else {
                            local_buffer.push_str(&format!("<div><h2>{}</h2><ul>", year));
                        }

                        for (exam, score) in year_scores {
                            if text_only {
                                local_buffer.push_str(&format!("\t{}: {}\n", exam, score));
                            } else {
                                local_buffer.push_str(&format!("<li><strong>{}</strong>: \
                                                                <span>{}</span></li>",
                                                               exam,
                                                               score));
                            }
                        }

                        if !text_only {
                            local_buffer.push_str("</ul></div>");
                        }

                        resp_buffer.push_str(&local_buffer);
                    }

                    let mut resp = iron::Response::with((Status::Ok, resp_buffer));
                    resp.headers
                        .set(headers::ContentType("text/html; charset=utf-8".parse().unwrap()));

                    Ok(resp)
                }
                Err(e) => Ok(iron::Response::with((Status::InternalServerError, e))),
            }
        }
        Err(e) => {
            match e {
                ScoreRequestError::ClientError(e) => {
                    Ok(iron::Response::with((Status::InternalServerError,
                                             format!("An internal client error occurred: {:?}",
                                                     e))))
                }
                ScoreRequestError::ReadError(e) => {
                    Ok(iron::Response::with((Status::InternalServerError,
                                             format!("An internal read error occurred: {:?}",
                                                     e))))
                }
                ScoreRequestError::SetCookieMissing => {
                    Ok(iron::Response::with((Status::InternalServerError,
                                             format!("The SetCookie header could not be found in \
                                                     The College Board's response."))))
                }
            }
        }
    }
}

macro_rules! get_node {
    ( $doc:expr, $select:expr ) => {
        match $doc.select($select) {
            Ok(nodes) => nodes,
            Err(_) => {
                return Err(format!("Unable to get node(s) at: {}", $select));
            }
        }
    };
}

macro_rules! get_text_contents {
    ( $select:expr, $selector:expr ) => {
        match $select.next() {
            Some(node) => node.text_contents(),
            None => {
                return Err(format!("Unable to get text contents for node(s) at: {}", $selector));
            }
        }
    };
}

fn parse_scores(page_html: String) -> Result<HashMap<String, Vec<(String, String)>>, String> {
    let doc = kuchiki::parse_html().one(page_html);

    let mut all_scores = HashMap::new();

    let score_years = match doc.select(".year-scores") {
        Ok(score_years) => {
            if score_years.count() < 1 {
                return Err(String::from("Either your login information was incorrect, you have no \
                                         AP scores, or something just broke."));
            }

            doc.select(".year-scores").unwrap()
        }
        Err(_) => {
            return Err(String::from("Unable to get node(s) at: .year-scores"));
        }
    };

    for score_year in score_years {
        let node = score_year.as_node();
        let mut year_node = get_node!(node, ".headline > h3");
        let year = get_text_contents!(year_node, ".headline > h3");

        let exams = get_node!(node, ".year-exams-container > .row-fluid.item");
        let mut scores = Vec::new();

        for exam in exams {
            let mut name_node = get_node!(exam.as_node(), ".span5 > h4");
            let mut score_node = get_node!(exam.as_node(), ".span5 > span > em");
            let name = get_text_contents!(name_node, ".span5 > h4");
            let score = get_text_contents!(score_node, ".span5 > span > em");

            scores.push((name, score));
        }

        all_scores.insert(year, scores);
    }

    Ok(all_scores)
}

enum ScoreRequestError {
    ClientError(hyper::Error),
    ReadError(Error),
    SetCookieMissing
}

fn get_raw_score_page<'a>(creds: (&'a str, &'a str)) -> Result<String, ScoreRequestError> {
    let mut client = Client::new();
    // can't follow them automatically, have to manually set the cookies on each redirect
    client.set_redirect_policy(RedirectPolicy::FollowNone);

    let username = percent_encoding::percent_encode(creds.0.as_bytes(),
                                                    percent_encoding::USERINFO_ENCODE_SET);
    let password = percent_encoding::percent_encode(creds.1.as_bytes(),
                                                    percent_encoding::USERINFO_ENCODE_SET);

    let req = client.post(LOGIN_URL)
        .header(ContentType("application/x-www-form-urlencoded".parse().unwrap()))
        .body(&format!("idp=ECL&isEncrypted=N&DURL=https%3A%2F%2Fapscore.collegeboard.org%2Fscores\
              %2Fview-your-scores&username={}&password={}&appid=287&formState=1",
              username,
              password))
		.send();
    let resp = match req {
        Ok(resp) => resp,
        Err(e) => {
            return Err(ScoreRequestError::ClientError(e))
        }
    };
    let mut buffer = String::new();

    match follow_redirect(&client, resp, &mut buffer) {
        Ok(_) => Ok(buffer),
        Err(err) => Err(err),
    }
}

fn follow_redirect(client: &Client,
                   mut resp: Response,
                   buffer: &mut String)
                   -> Result<(), ScoreRequestError> {
    if !resp.status.is_redirection() {
        match resp.read_to_string(buffer) {
            Ok(_) => {
                return Ok(());
            }
            Err(e) => {
                return Err(ScoreRequestError::ReadError(e));
            }
        }
    }

    let mut c_jar = CookieJar::new(b"f8f9eaf1ecdedff5e5b749c58115441e");
    let set_cookies = match resp.headers.get::<SetCookie>() {
        Some(cookie) => cookie,
        None => {
            return Err(ScoreRequestError::SetCookieMissing);
        }
    };
    set_cookies.apply_to_cookie_jar(&mut c_jar);
    let cookies = Cookie::from_cookie_jar(&c_jar);
    let req = client.post(resp.headers.get::<Location>().unwrap().as_str())
        .header(cookies)
        .send();
    let _resp = match req {
        Ok(_resp) => _resp,
        Err(e) => {
            return Err(ScoreRequestError::ClientError(e));
        }
    };

    follow_redirect(client, _resp, buffer)
}
