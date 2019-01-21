extern crate serde;
use serde::{Serialize, Deserialize};

/// This example, uses a simple structure `Point` that is serialized and deserialized to `JSON` using Rust's serde.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    fn as_json(&self)-> String
    {
        return serde_json::to_string(&self).unwrap()
    }

    fn from_json(s: &str)-> Self
    {
        return serde_json::from_str(s).unwrap()
    }
}


fn main() {
    let point = Point { x: 1, y: 2 };

    // Convert the Point to a JSON string.
    let serialized = point.as_json();

    // Prints serialized = {"x":1,"y":2}
    println!("serialized = {}", serialized);

    // Convert the JSON string back to a Point.
    let deserialized = Point::from_json(&serialized);

    // Prints deserialized = Point { x: 1, y: 2 }
    println!("deserialized = {:?}", deserialized);
}

#[cfg(test)]
mod tests {
    use super::*;
    /// This is a simple test case that demonstrates Rust unit tests.
    /// It verifies that the serialized point deserializes as expected. 
    #[test]
    fn test_point_serde() {
        let point = Point { x: 1, y: 2 };
        assert_eq!(point,  Point::from_json(&point.as_json()));
    }

    /// This demonstrates a way of writing a negative test case.
    #[test]
    #[should_panic(expected = "assertion failed: `(left == right)`")]
    fn test_specific_panic() {
        let p1 = Point { x: 1, y: 2 };
        let p2 = Point { x: 2, y: 2 };
        assert_eq!(p2,  Point::from_json(&p1.as_json()));
    }

}
