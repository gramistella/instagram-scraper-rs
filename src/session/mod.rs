//! # Session
//!
//! This module exposes the session for the instagram client

use std::sync::Arc;
use crate::{types::Comment, Authentication, InstagramScraperError, InstagramScraperResult, Post};
use reqwest_cookie_store::CookieStoreMutex;
use reqwest::{header, Client, ClientBuilder, Response};
use urlencoding::encode;

mod requests;
use requests::{
    BASE_URL, CHROME_WIN_USER_AGENT, LOGIN_URL, LOGOUT_URL, STORIES_USER_AGENT, X_CSRF_TOKEN,
};

pub use crate::{Stories, Story, User};

const DEFAULT_POST_AMOUNT: usize = 50;
const DEFAULT_COMMENTS_AMOUNT: usize = 50;

/// The session is a storage for values required by the instagram client to work.
/// It also exposes the instagram HTTP client
#[derive(Debug)]
pub struct Session {
    csrftoken: Option<String>,
    client: Client,

}

impl Default for Session {
    fn default() -> Self {
        Self {
            csrftoken: None,
            client: ClientBuilder::new()
                .cookie_store(true)
                .user_agent(STORIES_USER_AGENT)
                .build()
                .unwrap(),
        }
    }

}

impl Session {
    pub fn with_cookie_provider(cookie_provider: Arc<CookieStoreMutex>) -> Self {
        Self {
            csrftoken: None,
            client: ClientBuilder::new()
                .cookie_provider(Arc::clone(&cookie_provider))
                .user_agent(STORIES_USER_AGENT)
                .build()
                .unwrap(),
        }
    }
}

impl Session {
    /// Login into instagram account or as a guest based on provided authentication type
    pub(crate) async fn login(
        &mut self,
        authentication: Authentication,
    ) -> InstagramScraperResult<()> {
        let token = match authentication {
            Authentication::Guest => self.login_as_guest().await?,
            Authentication::UsernamePassword { username, password } => {
                self.login_as_user(username, password).await?
            }
        };
        debug!("login successful; csrf token: {}", token);
        self.csrftoken = Some(token);

        Ok(())
    }

    /// Scrape profile picture for provided username.
    ///
    /// Returns the image url
    pub async fn scrape_profile_pic(
        &mut self,
        user_id: &str,
    ) -> InstagramScraperResult<Option<String>> {
        self.restrict_authed()?;
        debug!("collecting profile pic for {}", user_id);
        let response = self
            .client
            .get(format!(
                "https://i.instagram.com/api/v1/users/{}/info/",
                user_id
            ))
            .send()
            .await?;
        Self::restrict_successful(&response)?;
        self.update_csrftoken(&response);
        let user_info = response
            .text()
            .await
            .map(|t| serde_json::from_str::<requests::UserInfoResponse>(&t).map(|u| u.user))?;
        let user_info = user_info?;
        if user_info.has_anonymous_profile_picture.unwrap_or_default() {
            debug!("user has anonymous profile picture");
            return Ok(None);
        }
        if let Some(url) = user_info.hd_profile_pic_url_info.url {
            debug!("found hd profile pic {}", url);
            Ok(Some(url.replace("\\u0026", "&")))
        } else {
            debug!("searching user profile pic in versions");
            Ok(user_info.hd_profile_pic_versions.and_then(|images| {
                images
                    .into_iter()
                    .rev()
                    .find_map(|img| img.url.map(|x| x.replace("\\u0026", "&")))
            }))
        }
    }

    /// Scrape shared data for user
    pub async fn scrape_shared_data_userinfo(
        &mut self,
        username: &str,
    ) -> InstagramScraperResult<User> {
        self.restrict_authed()?;
        debug!("collecting user info for {}", username);
        let response = self
            .client
            .get(format!(
                "https://i.instagram.com/api/v1/users/web_profile_info/?username={}",
                username
            ))
            .send()
            .await?;
        Self::restrict_successful(&response)?;
        self.update_csrftoken(&response);
        // Get the response text
        let response_text = response.text().await?;

        // Print the response text
        // println!("Response text: {}", response_text);

        // Proceed with your existing match logic, using the response_text variable
        match serde_json::from_str::<requests::WebProfileResponse>(&response_text) {
            Ok(web_profile_response) => Ok(web_profile_response.data.user),
            Err(err) => Err(err.into()),
        }
    }

    /// Scrape user stories
    pub async fn scrape_stories(
        &mut self,
        user_id: &str,
        max_highlight_stories: usize,
    ) -> InstagramScraperResult<Stories> {
        self.restrict_authed()?;
        debug!("collecting stories for {}", user_id);
        let main_stories = self.fetch_stories(format!("{}graphql/query/?query_hash=45246d3fe16ccc6577e0bd297a5db1ab&variables=%7B%22reel_ids%22%3A%5B%22{}%22%5D%2C%22tag_names%22%3A%5B%5D%2C%22location_ids%22%3A%5B%5D%2C%22highlight_reel_ids%22%3A%5B%5D%2C%22precomposed_overlay%22%3Afalse%7D", BASE_URL, user_id))
            .await?;
        debug!("collected main stories; collecting highlight stories");
        // fetch highlight stories
        if max_highlight_stories == 0 {
            warn!("max_highlight_stories is 0; return empty vector");
            return Ok(Stories {
                main_stories,
                highlight_stories: vec![],
            });
        }
        let highlight_stories_ids = self.fetch_highlighted_stories_ids(user_id).await?;
        debug!(
            "found {} ids for highlighted stories",
            highlight_stories_ids.len()
        );
        let mut highlight_stories = Vec::with_capacity(highlight_stories_ids.len());
        for chunk in highlight_stories_ids.chunks(3) {
            let id = chunk.join("%22%2C%22");
            debug!("fetching stories in chunk {}", id);
            highlight_stories.extend(
                self.fetch_stories(format!("{}graphql/query/?query_hash=45246d3fe16ccc6577e0bd297a5db1ab&variables=%7B%22reel_ids%22%3A%5B%5D%2C%22tag_names%22%3A%5B%5D%2C%22location_ids%22%3A%5B%5D%2C%22highlight_reel_ids%22%3A%5B%22{}%22%5D%2C%22precomposed_overlay%22%3Afalse%7D", BASE_URL, id)).await?
            );
            if highlight_stories.len() >= max_highlight_stories {
                debug!("reached maximum amount of highlight stories; leaving loop");
                break;
            }
        }
        // remove exceeding items
        if highlight_stories.len() > max_highlight_stories {
            let curlen = highlight_stories.len();
            for i in curlen..max_highlight_stories {
                highlight_stories.remove(i);
            }
        }

        Ok(Stories {
            main_stories,
            highlight_stories,
        })
    }

    /// Scrape posts published by user associated to `user_id`.
    /// You can provide the maximum amount of posts to fetch. Use usize::MAX to get all the available posts.
    /// Keep in mind that a GET request will be sent each 50 posts.
    pub async fn scrape_posts(
        &mut self,
        user_id: &str,
        max_posts: usize,
    ) -> InstagramScraperResult<Vec<Post>> {
        self.restrict_authed()?;
        debug!("collecting up to {} posts for {}", max_posts, user_id);
        let mut posts = Vec::new();
        let mut cursor = String::default();
        loop {
            let amount = if posts.len() + DEFAULT_POST_AMOUNT > max_posts {
                max_posts.saturating_sub(posts.len())
            } else {
                DEFAULT_POST_AMOUNT
            };

            debug!("collecting {} posts from {}", amount, cursor);
            let params = format!(
                r#"{{"id":"{}","first":{},"after":"{}"}}"#,
                user_id, amount, cursor
            );
            let response = self
                .client
                .get(format!(
                    "{}graphql/query/?query_hash=42323d64886122307be10013ad2dcc44&variables={}",
                    BASE_URL, params
                ))
                .send()
                .await?;
            Self::restrict_successful(&response)?;
            self.update_csrftoken(&response);
            match response
                .text()
                .await
                .map(|t| serde_json::from_str::<requests::PostResponse>(&t))
            {
                Err(err) => return Err(err.into()),
                Ok(Ok(post_response)) => {
                    let new_cursor = post_response.end_cursor().map(|x| x.to_string());
                    let response_posts = post_response.posts();
                    debug!("found {} posts", response_posts.len());
                    posts.extend(response_posts);
                    debug!(
                        "checking cursor; new cursor: {:?}; last cursor: {}",
                        new_cursor, cursor
                    );
                    if new_cursor == Some(cursor)
                        || new_cursor.is_none()
                        || posts.len() >= max_posts
                    {
                        debug!("leaving loop");
                        break;
                    }
                    cursor = new_cursor.unwrap();
                }
                Ok(Err(err)) => return Err(err.into()),
            }
        }
        Ok(posts)
    }
    pub async fn upload_reel(
        &mut self,
        user_id: &str,
        access_token: &str,
        video_url: &str,
        caption: &str,
    ) -> Result<(), InstagramScraperError> {

        // You only need these three
        // https://graph.facebook.com/v5.0/{ig-user-id}/media?video_url={video-url}&caption={caption}&access_token={access-token}
        // https://graph.facebook.com/v19.0/{ig-container-id}?fields=status_code
        // https://graph.facebook.com/v5.0/{ig-user-id}/media_publish?creation_id={container_id}&access_token={access-token}

        self.restrict_authed().unwrap();

        let full_url = format!(
            "https://graph.facebook.com/v5.0/{}/media?media_type=REELS&video_url={}&caption={}&access_token={}",
            user_id,
            encode(&video_url),
            encode(&caption),
            access_token
        );

        println!(" -> [+] Requesting media container from Instagram...");
        let response = self.client.post(full_url.clone()).send().await.unwrap();
        let response_text = response.text().await.unwrap().clone();
        let data: serde_json::Value = serde_json::from_str(&response_text).unwrap();
        let container_id = match data["id"].as_str() {
            Some(container_id) => container_id.to_string(),
            None => {
                let error_message = format!(
                    "Error while creating media container uploading:\n {}",
                    serde_json::to_string_pretty(&data).unwrap()
                );
                return Err(InstagramScraperError::Generic(error_message));
            }
        };

        //println!("Full url: \n{}", full_url);
        //println!("Response: {:?}", response_text);
        let mut status_code = String::new();
        while status_code != "FINISHED" {
            let response = self
                .client
                .get(format!(
                    "https://graph.facebook.com/v5.0/{}?fields=status_code,status&access_token={}",
                    container_id, access_token
                ))
                .send()
                .await
                .unwrap();
            let response_text = response.text().await.unwrap().clone();
            let data: serde_json::Value = serde_json::from_str(&response_text).unwrap();
            status_code = data["status_code"].as_str().unwrap().to_string();
            println!(
                " -> [+] Uploading reel to Instagram... Status code: {}",
                status_code
            );
            //println!("Status code: {}", status_code);

            if status_code == "ERROR" {
                let error_message = data["status"].as_str().unwrap().to_string();
                if error_message.contains("2207050") {
                    let error = "Error while uploading: \nThe app user's Instagram Professional account is inactive, checkpointed, or restricted. Advise the app user to sign in to the Instagram app and complete any actions the app requires to re-enable their account.";
                    return Err(InstagramScraperError::Generic(error.to_string()));
                } else if error_message.contains("2207026") {
                    let error = "Error while uploading: \nUnsupported video format. Advise the app user to upload an MOV or MP4";
                    return Err(InstagramScraperError::Generic(error.to_string()));
                } else {
                    let error = format!(
                        "Error while uploading reel: {}",
                        data["status"].as_str().unwrap().to_string()
                    );
                    return Err(InstagramScraperError::Generic(error.to_string()));
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(10));
        }

        println!(" +> [+] Publishing reel to Instagram...");
        let _response = self
            .client
            .post(format!(
                "https://graph.facebook.com/v5.0/{}/media_publish?creation_id={}&access_token={}",
                user_id, container_id, access_token
            ))
            .send()
            .await
            .unwrap();
        //let response_text = response.text().await.unwrap().clone();

        Ok(())
    }
    pub async fn download_reel(
        &mut self,
        shortcode: &str,
    ) -> Result<(String, String), InstagramScraperError> {
        self.restrict_authed().unwrap();

        let params = format!(r#"{{"shortcode":"{}"}}"#, shortcode);

        let encoded_params = encode(&params);
        //let query = "https://www.instagram.com/graphql/query?query_hash=2b0673e0dc4580674a88d426fe00ea90&variables=%7B%22shortcode%22%3A%22C3daVhdxlBT%22%7D";
        let query = format!(
            "{}graphql/query?query_hash=2b0673e0dc4580674a88d426fe00ea90&variables={}",
            BASE_URL, encoded_params
        );

        let query_string = query.to_string();

        let response = self.client.get(query_string).send().await.unwrap();

        let response_text = response.text().await.unwrap().clone();
        let data: serde_json::Value = serde_json::from_str(&response_text).unwrap();
        let video_url = if let Some(extracted_url) = data["data"]["shortcode_media"]["video_url"]
            .as_str()
            .clone()
        {
            //println!("Video URL: {}", video_url);
            extracted_url.to_string()
        } else {
            let pretty = serde_json::to_string_pretty(&data).unwrap();
            //println!("'video_url' field not found, data: \n{}", pretty);
            let error_text = format!("'video_url' field not found, \n{}", pretty);
            return Err(InstagramScraperError::FieldNotFound(error_text));
        };

        let mut caption = String::new();
        if let Some(edges) =
            data["data"]["shortcode_media"]["edge_media_to_caption"]["edges"].as_array()
        {
            if let Some(first_edge) = edges.first() {
                if let Some(text) = first_edge["node"]["text"].as_str() {
                    //println!("Found Caption: {}", text);
                    caption = text.to_string();
                } else {
                    //let pretty = serde_json::to_string_pretty(&data).unwrap();
                    //println!("'text' field not found \n{}", pretty);
                }
            } else {
                //let pretty = serde_json::to_string_pretty(&data).unwrap();
                //println!("'edges' array is empty \n{}", pretty);
            }
        } else {
            //let pretty = serde_json::to_string_pretty(&data).unwrap();
            //println!("'edges' field not found or is not an array \n{}", pretty);
        }

        return Ok((video_url, caption));
    }

    /// Scrape comments
    pub async fn scrape_comments(
        &mut self,
        shortcode: &str,
        max_comments: usize,
    ) -> InstagramScraperResult<Vec<Comment>> {
        self.restrict_authed()?;
        debug!(
            "collecting up to {} comments for {}",
            max_comments, shortcode
        );
        let mut comments = Vec::new();
        let mut cursor = String::default();
        loop {
            let amount = if comments.len() + DEFAULT_COMMENTS_AMOUNT > max_comments {
                max_comments.saturating_sub(comments.len())
            } else {
                DEFAULT_COMMENTS_AMOUNT
            };

            debug!("collecting {} comments from {}", amount, cursor);
            let params = format!(
                r#"{{"shortcode":"{}","first":{},"after":"{}"}}"#,
                shortcode, amount, cursor
            );
            let response = self
                .client
                .get(format!(
                    "{}graphql/query/?query_hash=33ba35852cb50da46f5b5e889df7d159&variables={}",
                    BASE_URL, params
                ))
                .send()
                .await?;
            Self::restrict_successful(&response)?;
            self.update_csrftoken(&response);
            match response
                .text()
                .await
                .map(|t| serde_json::from_str::<requests::CommentResponse>(&t))
            {
                Err(err) => return Err(err.into()),
                Ok(Ok(comment_response)) => {
                    let new_cursor = comment_response.end_cursor().map(|x| x.to_string());
                    let comment_response = comment_response.comments();
                    debug!("found {} comments", comment_response.len());
                    comments.extend(comment_response);
                    debug!(
                        "checking cursor; new cursor: {:?}; last cursor: {}",
                        new_cursor, cursor
                    );
                    if new_cursor == Some(cursor)
                        || new_cursor.is_none()
                        || comments.len() >= max_comments
                    {
                        debug!("leaving loop");
                        break;
                    }
                    cursor = new_cursor.unwrap();
                }
                Ok(Err(err)) => return Err(err.into()),
            }
        }
        Ok(comments)
    }

    // -- private

    /// Logout from Instagram
    pub(crate) async fn logout(&mut self) -> InstagramScraperResult<()> {
        if let Some(csrf_token) = self.csrftoken.as_deref() {
            let response = self
                .client
                .post(LOGOUT_URL)
                .header(header::USER_AGENT, CHROME_WIN_USER_AGENT)
                .form(&requests::LogoutRequest::new(csrf_token.to_string()).form())
                .send()
                .await?;
            Self::restrict_successful(&response)
        } else {
            error!("unauthenticated user; cannot logout");
            Err(InstagramScraperError::Unauthenticated)
        }
    }

    /// Returns whether session is authed
    pub(crate) fn authed(&self) -> bool {
        self.csrftoken.is_some()
    }

    /// Login to instagram as a guest
    async fn login_as_guest(&self) -> InstagramScraperResult<String> {
        debug!("authenticating as guest");
        self.request_csrftoken().await
    }

    /// Login to instagram as an authenticated user
    async fn login_as_user(
        &mut self,
        username: String,
        password: String,
    ) -> InstagramScraperResult<String> {
        debug!("authenticating with username and password");
        let token = self.request_csrftoken().await?;

        let response = self
            .client
            .post(LOGIN_URL)
            .form(
                requests::UsernamePasswordLoginRequest::new(username, password)
                    .form()
                    .as_slice(),
            )
            .header(header::REFERER, BASE_URL)
            .header(X_CSRF_TOKEN, token.clone())
            .header("X-Requested-With", "XMLHttpRequest")
            .send()
            .await?;
        Self::restrict_successful(&response)?;
        debug!("setting cookies received from response");

        // let cookies = response.cookies().collect::<Vec<_>>();
        // println!("Cookies: {:?}", cookies);

        let body: requests::UsernamePasswordLoginResponse = response.json().await?;
        if body.authenticated {
            debug!("user authenticated successfully");
            Ok(token)
        } else {
            error!("login failed: {:?}; {:?}", body.status, body.message);
            Err(InstagramScraperError::AuthenticationFailed {
                status: body.status.unwrap_or_default(),
                message: body.message.unwrap_or_default(),
            })
        }
    }

    async fn request_csrftoken(&self) -> InstagramScraperResult<String> {
        let response = self
            .client
            .get(BASE_URL)
            .header(header::REFERER, BASE_URL)
            .send()
            .await?;
        Self::restrict_successful(&response)?;
        trace!("login status: {}", response.status());
        let mut cookies = response.cookies();
        match cookies
            .find(|x| x.name() == "csrftoken")
            .map(|x| x.value().to_string())
        {
            Some(cookie) => Ok(cookie),
            None => Err(InstagramScraperError::CsrfTokenIsMissing),
        }
    }

    /// Update csrf token
    fn update_csrftoken(&mut self, response: &Response) {
        let mut cookies = response.cookies();
        if let Some(token) = cookies
            .find(|x| x.name() == "csrftoken")
            .map(|x| x.value().to_string())
        {
            debug!("new csrftoken: {}", token);
            self.csrftoken = Some(token);
        }
    }

    /// Fetch stories from url
    async fn fetch_stories(&mut self, url: String) -> InstagramScraperResult<Vec<Story>> {
        debug!("fetching user stories at {}", url);
        let response = self.client.get(url).send().await?;
        match response
            .text()
            .await
            .map(|t| serde_json::from_str::<requests::ReelsMedia>(&t).map(|i| i.items()))
        {
            Err(err) => Err(err.into()),
            Ok(Ok(stories)) => Ok(stories.into_iter().map(Story::from).collect()),
            Ok(Err(err)) => Err(err.into()),
        }
    }

    /// Fetch highlighted stories ids
    async fn fetch_highlighted_stories_ids(
        &mut self,
        user_id: &str,
    ) -> InstagramScraperResult<Vec<String>> {
        let response = self.client.get(format!("{}graphql/query/?query_hash=c9100bf9110dd6361671f113dd02e7d6&variables=%7B%22user_id%22%3A%22{}%22%2C%22include_chaining%22%3Afalse%2C%22include_reel%22%3Afalse%2C%22include_suggested_users%22%3Afalse%2C%22include_logged_out_extras%22%3Afalse%2C%22include_highlight_reels%22%3Atrue%2C%22include_related_profiles%22%3Afalse%7D", BASE_URL, user_id)).send().await?;
        match response
            .text()
            .await
            .map(|t| serde_json::from_str::<requests::HighlightReels>(&t).map(|i| i.node_ids()))
        {
            Err(err) => Err(err.into()),
            Ok(Ok(ids)) => Ok(ids),
            Ok(Err(err)) => Err(err.into()),
        }
    }

    /// This function puts a restriction on a function flow to return in case of an unsuccessful status code in the HTTP response.
    ///
    /// it must be called as `Self::restrict_successful(&response)?;`
    fn restrict_successful(response: &reqwest::Response) -> InstagramScraperResult<()> {
        debug!("response status {}", response.status());
        match response.status().is_success() {
            true => Ok(()),
            false => Err(InstagramScraperError::from(response.status())),
        }
    }

    /// This function puts a restriction on a function flow to return in case we're not authenticated
    fn restrict_authed(&self) -> InstagramScraperResult<()> {
        trace!("checking authentication");
        if self.authed() {
            trace!("authed");
            Ok(())
        } else {
            error!("unauthenticated user, but authentication is required");
            Err(InstagramScraperError::Unauthenticated)
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_initialize_session() {
        let session = Session::default();
        assert!(session.csrftoken.is_none());
        assert!(!session.authed());
    }

    #[tokio::test]
    async fn should_login_as_guest() {
        let mut session = Session::default();
        assert!(session.login(Authentication::Guest).await.is_ok());
        assert!(session.authed());
        assert!(session.logout().await.is_ok());
    }

    #[tokio::test]
    async fn should_logout_as_guest() {
        let mut session = Session::default();
        assert!(session.login(Authentication::Guest).await.is_ok());
        assert!(session.authed());
        assert!(session.logout().await.is_ok());
    }

    #[tokio::test]
    async fn should_login_as_user_and_scrape_all() {
        let mut session = user_login().await;
        assert!(session.authed());
        // profile pic
        let user_id = session
            .scrape_shared_data_userinfo("bigluca.marketing")
            .await
            .unwrap()
            .id;
        assert!(session
            .scrape_profile_pic(&user_id)
            .await
            .unwrap()
            .is_some());
        // Stories
        let user_id = session
            .scrape_shared_data_userinfo("tamadogecoin")
            .await
            .unwrap()
            .id;
        let stories = session.scrape_stories(&user_id, 7).await.unwrap();
        assert_eq!(stories.highlight_stories.len(), 7);
        let user_id = session
            .scrape_shared_data_userinfo("tamadogecoin")
            .await
            .unwrap()
            .id;
        // Posts
        assert!(session.scrape_posts(&user_id, 100).await.is_ok());
        let user_id = session
            .scrape_shared_data_userinfo("chiaraferragni")
            .await
            .unwrap()
            .id;
        let latest_posts = session.scrape_posts(&user_id, 10).await.unwrap();
        assert_eq!(latest_posts.len(), 10);
        // Comments
        let last_post = latest_posts.get(0).unwrap();
        assert!(session
            .scrape_comments(&last_post.shortcode, 100)
            .await
            .is_ok());

        // logout
        assert!(session.logout().await.is_ok());
    }

    #[tokio::test]
    async fn should_return_error_if_not_authed() {
        let mut session = Session::default();
        assert!(session
            .scrape_shared_data_userinfo("tamadogecoin")
            .await
            .is_err());
        assert!(session.scrape_comments("53718238932", 10).await.is_err());
        assert!(session.scrape_posts("53718238932", 10).await.is_err());
        assert!(session.scrape_profile_pic("53718238932").await.is_err());
        assert!(session.scrape_stories("53718238932", 10).await.is_err());
    }

    async fn user_login() -> Session {
        let username =
            std::env::var("INSTAGRAM_USERNAME").expect("missing env key INSTAGRAM_USERNAME");
        let password =
            std::env::var("INSTAGRAM_PASSWORD").expect("missing env key INSTAGRAM_PASSWORD");
        let mut session = Session::default();
        assert!(session
            .login(Authentication::UsernamePassword { username, password })
            .await
            .is_ok());

        session
    }
}
