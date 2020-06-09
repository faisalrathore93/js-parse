use json;
use regex::Regex;

pub fn find_endpoints(domain: &str, content: &str) -> Vec<String> {
    // at first, only match single relative urls

    let mut endpoints: Vec<String> = Vec::with_capacity(0xff);

    // more or less ugly regex since rust doesn't support some features
    let re = Regex::new("=[ ]?['\"]/[a-zA-Z0-9.!_:-][a-zA-Z0-9.!_:/-]+[;\"'#?]").unwrap(); // e.g. ="/some/relative/url.php"

    for endpoint in re.find_iter(content) {
        let mut endpoint = endpoint.as_str().to_string();

        // remove leading and trailing not-part-of-the-path characters
        endpoint.pop();
        endpoint.remove(0);
        endpoint.remove(0);

        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }

    // now, find relative urls including the domain name and seperate them

    let re = Regex::new(&format!(
        r"(https?:){{0,1}}(//){{0,1}}{}/([A-Za-z0-9._~!/-]|%[a-zA-Z0-9]{{2}})+",
        domain.replace(".", r"\.")
    ))
    .unwrap();

    for endpoint in re.find_iter(content) {
        let mut endpoint = endpoint.as_str().to_string();

        // delete everything until index of given domain in match plus domain length
        let n_delete = endpoint.find(domain).unwrap() + domain.chars().count();

        for _ in 0..n_delete {
            endpoint.remove(0);
        }

        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    return endpoints;
}

pub fn find_subdomains(domain: &str, content: &str) -> Vec<String> {
    /*
     * 1. find potential subdomains with regex
     * 2. verify size is no greater than 255
     * 3. verify size of each part is no greater than 63
     * 4. each part starts and ends with an alphanumeric character
     *
     */

    let mut subdomains: Vec<String> = Vec::with_capacity(0xff);

    let re = Regex::new(&format!(r"[A-Za-z0-9.-]+\.{}", domain.replace(".", r"\."))).unwrap(); // e.g. www.domain.com

    for sub in re.find_iter(content) {
        let sub = sub.as_str();

        let mut valid = true;

        // total size check
        if sub.chars().count() > 0xff {
            continue;
        }

        for part in sub.split(".") {
            let len = part.chars().count();

            // part size check
            if len > 0x3f {
                valid = false;
                break;
            }

            let bytes = part.as_bytes();

            // ascii value not greater than 'z'
            if bytes[0] > 0x7a || bytes[len - 1] > 0x7a {
                valid = false;
                break;
            }

            // ascii value not smaller than '0'
            if bytes[0] < 0x30 || bytes[len - 1] < 0x30 {
                valid = false;
                break;
            }

            // ascii value not greater than '9' AND not smaller than 'A'
            if (bytes[0] > 0x39 && bytes[0] < 0x41)
                || (bytes[len - 1] > 0x39 && bytes[len - 1] < 0x41)
            {
                valid = false;
                break;
            }
        }

        if !valid {
            continue;
        }

        if !subdomains.contains(&sub.to_string()) {
            subdomains.push(sub.to_string());
        }
    }
    return subdomains;
}

pub fn find_parameter(content: &str) -> Vec<String> {
    let mut parameter: Vec<String> = Vec::with_capacity(0xff);

    let re = Regex::new(r"[?&][A-Za-z0-9%,.~*/!_-]+=").unwrap(); // e.g. ?query=

    for param in re.find_iter(content) {
        let mut param = param.as_str().to_string();

        // remove leading and trailing not-part-of-the-parameter characters
        param.pop();
        param.remove(0);

        if !parameter.contains(&param) {
            parameter.push(param);
        }
    }
    return parameter;
}

pub fn find_header(content: &str) -> Vec<String> {
    let mut headers: Vec<String> = Vec::with_capacity(0xff);

    let re = Regex::new(r"X-[a-zA-Z0-9_-]+").unwrap(); // e.g. X-Secret-Header

    for header in re.find_iter(content) {
        let header = header.as_str().to_string();

        if !headers.contains(&header) {
            headers.push(header);
        }
    }
    return headers;
}

pub fn find_api_keys(content: &str) -> Vec<String> {
    let mut api_keys: Vec<String> = Vec::with_capacity(0xff);

    let keys_json = json::parse(
        r#"
    
    {
        "Artifactory Token":    "AKC[a-zA-Z0-9]{10,}",
        "Artifactory Password": "AP[0-9A-F][a-zA-Z0-9]{8,}",
        "Mailchamp API Key":    "[0-9a-f]{32}-us[0-9]{1,2}",
        "Mailgun API Key":      "key-[0-9a-zA-Z]{32}",
        "Picatic API Key":      "sk_live_[0-9a-z]{32}",
        "Slack Token":          "xox[baprs]-[0-9a-zA-Z]{10,48}",
        "Stripe API Key":       "(?:r|s)k_live_[0-9a-zA-Z]{24}",
        "Twilio API Key":       "SK[0-9a-fA-F]{32}"
    }

    "#,
    )
    .unwrap();

    for (name, regex) in keys_json.entries() {
        let re = Regex::new(regex.as_str().unwrap()).unwrap();

        for key in re.find_iter(content) {
            let key = key.as_str().to_string();

            if !api_keys.contains(&key) {
                api_keys.push(format!("{}|{}", name.to_string(), key));
            }
        }
    }
    return api_keys;
}
