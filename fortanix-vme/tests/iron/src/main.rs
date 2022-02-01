use iron::prelude::*;
use iron::{BeforeMiddleware, AfterMiddleware, typemap};
use std::sync::atomic::{AtomicU32, Ordering};
use time;

static NUM_SUCCEEDING_CONNECTIONS: AtomicU32 = AtomicU32::new(0);

fn signal_success() {
    let mut count = NUM_SUCCEEDING_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    println!("count = {}", count);
    count = count + 1;
    if count == 3 {
        std::process::exit(0);
    }
}

struct ResponseTime;

impl typemap::Key for ResponseTime { type Value = time::Instant; }

impl BeforeMiddleware for ResponseTime {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        req.extensions.insert::<ResponseTime>(time::Instant::now());
        Ok(())
    }
}

impl AfterMiddleware for ResponseTime {
    fn after(&self, req: &mut Request, res: Response) -> IronResult<Response> {
        let delta = time::Instant::now() - *req.extensions.get::<ResponseTime>().unwrap();
        println!("# Request took: {} ns", delta.whole_nanoseconds());
        signal_success();
        Ok(res)
    }
}

fn hello_world(_: &mut Request) -> IronResult<Response> {
    Ok(Response::with((iron::status::Ok, "Hello World")))
}

fn main() {
    let mut chain = Chain::new(hello_world);
    chain.link_before(ResponseTime);
    chain.link_after(ResponseTime);
    let iron = Iron::new(chain);
    iron.http("127.0.0.1:3000").unwrap();
}
