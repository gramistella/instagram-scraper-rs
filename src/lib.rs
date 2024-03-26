#![crate_name = "instagram_scraper_rs"]
#![crate_type = "lib"]

//! # Instagram-scraper-rs
//!
//! instagram-scraper-rs is a Rust library that scrapes and downloads an instagram user's photos and videos. Use responsibly.
//! It is basically a 1:1 copy of the Python [Instagram-scraper](https://github.com/arc298/instagram-scraper) cli application.
//!
//! ## Features
//!
//! - Query profile information
//! - Collect the user's profile picture
//! - Collect users' posts
//! - Collect users' stories
//! - Totally async
//!
//! ## Get started
//!
//! ### Add instagram-scraper-rs to your Cargo.toml 🦀
//!
//! ```toml
//! instagram-scraper-rs = "^0.1.0"
//! ```
//!
//! Supported features are:
//!
//! - `no-log`: disable logging
//! - `native-tls` (*default*): use native-tls for reqwest
//! - `rustls`: use rustls for reqwest (you must disable default features)
//!
//! ### Instagram scraper setup
//!
//! ```rust,ignore
//! use instagram_scraper_rs::InstagramScraper;
//!
//! // setup the scraper
//! let mut scraper = InstagramScraper::default()
//!     .authenticate_with_login(username, password);
//! scraper.login().await?;
//! // get user info; required to query other data
//! let user = scraper.scrape_userinfo("tamadogecoin").await?;
//! // collect user's stories and up to 10 highlighted stories
//! let stories = scraper.scrape_user_stories(&user.id, 10).await?;
//! // collect last 10 posts
//! let posts = scraper.scrape_posts(&user.id, 10).await?;
//! // logout
//! scraper.logout().await;
//! ```
//!

#![doc(html_playground_url = "https://play.rust-lang.org")]

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

mod errors;
mod session;
mod types;

use session::Session;
use types::Authentication;

// exports
pub use errors::{InstagramScraperError, InstagramScraperResult};
pub use types::{Comment, Post, Stories, Story, StorySource, User};

/// instagram scraper client
#[derive(Debug)]
pub struct InstagramScraper {
    auth: Authentication,
    pub session: Session,
}

impl InstagramScraper {
    /// Configure scraper to authenticate with username/password
    pub fn authenticate_with_login(
        &mut self,
        username: impl ToString,
        password: impl ToString,
    ) -> &mut Self {
        self.auth = Authentication::UsernamePassword {
            username: username.to_string(),
            password: password.to_string(),
        };
        self
    }

    /// Login to instagram
    pub async fn login(&mut self) -> InstagramScraperResult<()> {
        self.session.login(self.auth.clone()).await
    }

    /// Logout from instagram account
    pub async fn logout(&mut self) -> InstagramScraperResult<()> {
        debug!("signin out from Instagram");
        self.session.logout().await?;
        debug!("logout ok, reinitializing session");
        // re-initialize session
        self.session = Session::default();
        Ok(())
    }

    /// Scrape profile HD picture if any. Returns the URL.
    /// The user id can be retrieved with `scrape_userinfo`
    pub async fn scrape_profile_pic(
        &mut self,
        user_id: &str,
    ) -> InstagramScraperResult<Option<String>> {
        self.session.scrape_profile_pic(user_id).await
    }

    /// Scrape profile HD picture if any. Returns the URL.
    /// The user id can be retrieved with `scrape_userinfo`
    /// You can provide the maximum amount of posts to fetch. Use usize::MAX to get all the available stproes.
    /// Keep in mind that a GET request will be sent each 3 highlighted stories.
    pub async fn scrape_user_stories(
        &mut self,
        user_id: &str,
        max_highlight_stories: usize,
    ) -> InstagramScraperResult<Stories> {
        self.session
            .scrape_stories(user_id, max_highlight_stories)
            .await
    }

    /// Scrape user info
    pub async fn scrape_userinfo(&mut self, username: &str) -> InstagramScraperResult<User> {
        self.session.scrape_shared_data_userinfo(username).await
    }

    /// Scrape posts from user.
    /// You can provide the maximum amount of posts to fetch. Use usize::MAX to get all the available posts.
    /// Keep in mind that a GET request will be sent each 50 posts.
    pub async fn scrape_posts(
        &mut self,
        user_id: &str,
        max_posts: usize,
    ) -> InstagramScraperResult<Vec<Post>> {
        if max_posts == 0 {
            warn!("max_posts is 0; return empty vector");
            return Ok(vec![]);
        }
        self.session.scrape_posts(user_id, max_posts).await
    }

    pub async fn download_reel(
        &mut self,
        shortcode: &str,
    ) -> InstagramScraperResult<(String, String)> {
        let (url, caption) = self.session.download_reel(shortcode).await?;
        Ok((url, caption))
    }

    pub async fn upload_reel(
        &mut self,
        user_id: &str,
        access_token: &str,
        url: &str,
        caption: &str,
    ) -> InstagramScraperResult<()> {
        match self
            .session
            .upload_reel(user_id, access_token, url, caption)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Scrape comments from a post.
    /// You can provide the maximum amount of comments to fetch. Use usize::MAX to get all the available posts.
    /// Keep in mind that a GET request will be sent each 50 posts.
    pub async fn scrape_comments(
        &mut self,
        post: &Post,
        max_comments: usize,
    ) -> InstagramScraperResult<Vec<Comment>> {
        if max_comments == 0 {
            warn!("max_comments is 0; return empty vector");
            return Ok(vec![]);
        }
        debug!("collecting comments for post {}", post.id);
        self.session
            .scrape_comments(&post.shortcode, max_comments)
            .await
    }
}

impl Default for InstagramScraper {
    fn default() -> Self {
        Self {
            auth: Authentication::Guest,
            session: Session::default(),
        }
    }
}

impl InstagramScraper {
    pub fn with_cookie_store(cookie_store_path: &str) -> Self {
        Self {
            auth: Authentication::Guest,
            session: Session::with_cookie_store(cookie_store_path),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[tokio::test]
    async fn should_login_and_logout() {
        let mut scraper = InstagramScraper::default();
        assert!(scraper.login().await.is_ok());
        assert!(scraper.logout().await.is_ok());
    }

    #[tokio::test]
    async fn should_return_empty_vec_if_scraping_0_posts() {
        let mut scraper = InstagramScraper::default();
        assert!(scraper.scrape_posts("aaa", 0).await.unwrap().is_empty());
    }
}
