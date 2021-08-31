use std::{collections::{BTreeSet, HashMap}, error::Error};

use url::Url;

use html5ever::parse_document;
use html5ever::tendril::TendrilSink;
use markup5ever_rcdom::{RcDom, Handle, NodeData};

fn each_element(node: &Handle, f: &mut dyn FnMut(&Handle)) {
    if let NodeData::Element { .. } = node.data {
        f(node)
    }
    for node in &**node.children.borrow() {
        each_element(node, f)
    }
}

#[derive(Debug)]
struct Crawler {
    root: Url,
    to_fetch: Vec<Url>,
    contents: HashMap<Url, Vec<Url>>,
}

impl Crawler {
    fn new(root: &str) -> Result<Crawler, url::ParseError> {
        let root = Url::parse(&root)?;
        Ok(Crawler {
            to_fetch: vec![root.clone()],
            contents: Default::default(),
            root,
        })
    }

    fn crawl(&mut self) -> Result<(), Box<dyn Error>> {
        while let Some(url) = self.to_fetch.pop() {
            eprintln!("Crawling {}", url);
            self.contents.entry(url.clone()).or_insert(vec![]);
            let response = reqwest::blocking::get(url.clone())?;
            if !response.status().is_success() {
                panic!("{:?} fetching {}", response.status(), url)
            }
            let dom = parse_document(RcDom::default(), Default::default()).one(response.text()?);
            each_element(&dom.document, &mut |node| {
                if let NodeData::Element { ref name, ref attrs, .. } = node.data {
                    if name.local != *"a" {
                        return
                    }
                    for attr in &**attrs.borrow() {
                        if attr.name.local != *"href" {
                            continue
                        }
                        let s = attr.value.to_string();
                        match url::Url::parse(&s) {
                            Err(url::ParseError::RelativeUrlWithoutBase) => {},
                            _ => continue
                        }
                        let new_url = url.join(&s).unwrap();
                        
                        if self.should_crawl(&new_url) {
                            if !self.contents.contains_key(&new_url) && !self.to_fetch.contains(&new_url) {
                                self.to_fetch.push(new_url)
                            }
                        } else if self.should_download(&new_url) {
                            self.contents.get_mut(&url).unwrap().push(new_url);
                        }
                    }
                }
            });
        }
        Ok(())
    }

    fn is_child_url_no_query(&self, url: &Url) -> bool {
        if url.query().is_some() || !url.as_str().starts_with(self.root.as_str()) {
            return false
        }
        match (self.root.path_segments().map(|s| s.peekable()), url.path_segments()) {
            (Some(mut r), Some(mut u)) => {
                // check root is a prefix path of url
                loop {
                    let r_cur = r.next();
                    if r_cur == Some("") && r.peek() == None {
                        return true
                    } else if r_cur == None {
                        break
                    } else if r_cur != u.next() {
                        return false
                    }
                }
                // check url doesn't contain directory traversal
                for s in u {
                    if s == ".." {
                        return false
                    }
                }
                true
            }
            _ => false
        }
    }

    fn should_crawl(&self, url: &Url) -> bool {
        fn contains_ignored_text(s: &str) -> bool {
            [
                "windows",
                "rhel",
                "suse",
                "fedora",
                "desktop",
                "ubuntu18",
                "ubuntuserver18",
                "centos",
                "latest",
                "docs",
                "tools",
                "sgx_repo",
                "debian_pkgs",
            ].iter().any(|word| s.contains(word))
        }

        self.is_child_url_no_query(url)
        && url.path().chars().next_back() == Some('/')
        && !contains_ignored_text(&url.path().to_ascii_lowercase())
    }

    fn should_download(&self, url: &Url) -> bool {
        self.is_child_url_no_query(url)
        && url.path().chars().next_back() != Some('/')
        && url.path().to_ascii_lowercase().contains("driver")
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut crawler = Crawler::new("https://download.01.org/intel-sgx/")?;
    crawler.crawl()?;
    let sorted: BTreeSet<_> = crawler.contents.into_iter().flat_map(|(_, files)| files.into_iter()).collect();
    for file in sorted {
        println!("{}", file);
    }
    Ok(())
}
