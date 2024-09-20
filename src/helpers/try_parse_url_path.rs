use std::error::Error;
use url::Url;

fn try_parse_url(url: &str) -> Result<Url, Box<dyn Error>> {
    Url::parse(url).map_err(|e| e.into())
}

pub fn try_parse_url_path(url: &str) -> Option<String> {
    let full_url = if url.starts_with("/") {
        format!("http://localhost{}", url)
    } else {
        url.to_string()
    };

    match try_parse_url(&full_url) {
        Ok(parsed) => {
            let path = parsed.path();
            if path.is_empty() {
                Some("/".to_string())
            } else {
                Some(path.to_string())
            }
        }
        Err(_) => None,
    }
}
