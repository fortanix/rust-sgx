use std::any::TypeId;
use std::cell::Cell;
use std::cmp::Ordering;
use std::fmt;
use std::ops::{Index, IndexMut};

use fnv::{FnvHashMap, FnvHashSet};
use petgraph::graph::DiGraph;
use yansi::Paint;

use crate::{paintalt, SgxSupport};
use super::debug;

pub trait DetectItem: Print + DebugSupport + Update + mopa::Any {
    fn default() -> Box<dyn DetectItem> where Self: Sized;
}
mopafy!(DetectItem);

pub trait Update {
    fn update(&mut self, _support: &SgxSupport) {}
}

pub trait Name {
    fn name(&self) -> &'static str;
}

#[derive(Copy, Clone, Deserialize, Serialize, Debug, PartialEq)]
pub enum BuildType {
    Generic,
    EnclaveOSPreInstall,
    EnclaveOSPostInstall,
}

impl Default for BuildType {
    fn default() -> Self {BuildType::Generic}
}

pub trait Print: Name {
    fn try_supported(&self) -> Option<Status> {
        Some(self.supported())
    }

    fn supported(&self) -> Status {
        panic!("Unable to answer supported query for {}", self.name())
    }

    fn print(&self, level: usize) {
        println!(
            "{:width$}{}{}",
            "",
            self.try_supported().map_or(Paint::new(""), Status::paint),
            self.name(),
            width = level * 2
        );
    }
}

pub trait DebugSupport {
    /// # Panics
    /// May panic if `supported` returns `Status::Supported`.
    fn debug(&self, _out: debug::Output, _items: &DetectItemMap) -> fmt::Result { Ok(()) }
}

impl<T: Print + DebugSupport + Update + Default + 'static> DetectItem for T {
    #[inline]
    fn default() -> Box<dyn DetectItem> {
        Box::new(T::default())
    }
}

#[allow(non_camel_case_types)]
pub trait __missing_dependency_attribute__<T> {}

pub trait Dependency<T: DetectItem>: DetectItem + __missing_dependency_attribute__<T> {
    const CONTROL_VISIBILITY: bool = false;

    fn update_dependency(&mut self, dependency: &T, support: &SgxSupport) {
        let _ = dependency;
        self.update(support)
    }
}

pub type DetectItemInitFn = fn() -> Box<dyn DetectItem>;

pub type DependencyUpdateFn =
    fn(&dyn DetectItem, &mut dyn DetectItem, &SgxSupport, &Cell<bool>);

#[allow(unused)]
struct Category;
#[allow(unused)]
struct Test;

pub type TypeIdIdx = u8;

#[derive(Default)]
pub struct DetectItemMap {
    next: TypeIdIdx,
    map: FnvHashMap<TypeId, TypeIdIdx>,
    store: Vec<Box<dyn DetectItem>>
}

impl DetectItemMap {
    fn allocate_index(&mut self, v: TypeId) -> TypeIdIdx {
        let next = &mut self.next;
        *self.map.entry(v).or_insert_with(|| {
            let this = *next;
            *next = this
                .checked_add(1)
                .expect("Too many nodes, increase index type size");
            this
        })
    }

    pub fn allocate_raw(&mut self, v: TypeId, f: DetectItemInitFn) -> TypeIdIdx {
        let idx = self.allocate_index(v);

        match self.store.len().cmp(&(idx as usize)) {
            Ordering::Less => panic!("Didn't call DetectItemMap::get_index in sequential order"),
            Ordering::Equal => self.store.push(f()),
            Ordering::Greater => {},
        }

        assert_eq!(v, <dyn DetectItem as mopa::Any>::get_type_id(&*self.store[idx as usize]));

        idx
    }

    pub fn allocate<T: DetectItem>(&mut self) -> TypeIdIdx {
        self.allocate_raw(TypeId::of::<T>(), T::default)
    }

    pub fn as_slice_mut(&mut self) -> &mut [Box<dyn DetectItem>] {
        &mut self.store
    }

    pub fn lookup<T: DetectItem>(&self) -> &T {
        self.store[self.map[&TypeId::of::<T>()] as usize].downcast_ref().unwrap()
    }
}

impl Index<TypeIdIdx> for DetectItemMap {
    type Output = dyn DetectItem;

    fn index(&self, index: TypeIdIdx) -> &dyn DetectItem {
        &*self.store[index as usize]
    }
}

impl IndexMut<TypeIdIdx> for DetectItemMap {
    fn index_mut(&mut self, index: TypeIdIdx) -> &mut dyn DetectItem {
        &mut*self.store[index as usize]
    }
}

pub struct DependencyInfo {
    pub update_fn: DependencyUpdateFn,
    pub hidden: Cell<bool>,
}

#[derive(Default)]
pub struct Tests {
    pub functions: DetectItemMap,
    pub dependencies: DiGraph<(), DependencyInfo, TypeIdIdx>,
    pub ui_hidden: FnvHashSet<TypeIdIdx>,
    pub ui_children: Vec<Vec<TypeIdIdx>>,
    pub ui_root: TypeIdIdx,
}

pub fn set_at_index<T: Default>(v: &mut Vec<T>, index: usize, value: T) {
    if v.len() <= index {
        if let Some(additional) = (index + 1).checked_sub(v.capacity()) {
            v.reserve(additional)
        }
        while v.len() <= index {
            v.push(T::default());
        }
    }
    v[index] = value;
}

macro_rules! tests_inner {
    ( node $tests:ident $(@$meta:tt)* $name:expr => Category($test:ident, tests: { $($(@$cmeta:tt)* $cname:expr => $cty:ident $cparam:tt, )* } ) ) => {
        {
            let idx = tests_inner!( node_common $tests $test $name );

            let ui_children = vec![ $(tests_inner!( node $tests $(@$cmeta)* $cname => $cty $cparam ),)* ];

            $(
                #[dependency]
                impl Dependency<tests_inner!( typename $cparam )> for $test {
                    tests_inner!( meta_foreach control_visibility $($cmeta)* );
                    tests_inner!( meta_foreach [update_supported($cparam)] $($cmeta)* );
                }
            )*

            $crate::tests::scaffold::set_at_index(&mut $tests.ui_children, idx as usize, ui_children);

            idx
        }
    };
    ( node $tests:ident $(@$meta:tt)* $name:expr => Test($test:ident) ) => {
        tests_inner!( node_common $tests $test $name )
    };

    ( node_common $tests:ident $test:ident $name:expr ) => {
        {
            impl $crate::tests::Name for $test {
                fn name(&self) -> &'static str {
                    $name
                }
            }

            $tests.functions.allocate::<$test>()
        }
    };
    ( typename ( $name:ident $($rest:tt)* ) ) => {
        $name
    };

    ( meta_foreach $search:tt $meta:tt $($rest:tt)* ) => {
        tests_inner!( meta_check $meta );
        tests_inner!( meta_impl $search $meta );
        tests_inner!( meta_foreach $search $($rest)* );
    };
    ( meta_foreach $search:tt ) => {};
    ( meta_check [control_visibility $($rest:tt)*] ) => {};
    ( meta_check [update_supported $($rest:tt)*] ) => {};
    ( meta_check [$name:tt $($rest:tt)*] ) => {
        compile_error!(concat!("Unknown attribute: ", stringify!($name $($rest)*)));
    };

    ( meta_impl control_visibility [control_visibility] ) => {
        const CONTROL_VISIBILITY: bool = true;
    };
    ( meta_impl control_visibility [control_visibility $($rest:tt)*] ) => {
        compile_error!(concat!("Invalid control_visibility attribute: ", stringify!(control_visibility $($rest)*)));
    };
    ( meta_impl control_visibility $($rest:tt)* ) => {};

    ( meta_impl [update_supported($cparam:tt)] [update_supported = $var:ident] ) => {
        fn update_dependency(&mut self, dependency: &tests_inner!( typename $cparam ), support: &SgxSupport) {
            self.$var = dependency.supported();
            self.update(support)
        }
    };
    ( meta_impl [update_supported($cparam:tt)] [update_supported $($rest:tt)*] ) => {
        compile_error!(concat!("Invalid update_supported attribute: ", stringify!(update_supported $($rest)*)));
    };
    ( meta_impl [update_supported($cparam:tt)] $($rest:tt)* ) => {};
}

macro_rules! tests {
    ($($rest:tt)*) => {{
        let mut tests = Tests::default();

        let ui_root = tests_inner!( node tests "root" => Category(Root, tests: { $($rest)* } ) );
        assert_eq!(tests.ui_root, ui_root);

        tests
    }};
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Status {
    Supported,
    Unsupported,
    Fatal,
    Unknown,
}

impl Status {
    pub fn paint(self) -> Paint<&'static str> {
        use yansi::{Color, Style};
        match self {
            Status::Supported => paintalt("✔  ", "yes ").with_style(Style::new(Color::Green)),
            Status::Unsupported => paintalt("✘  ", "no  ").with_style(Style::new(Color::Yellow)),
            Status::Fatal => paintalt("✘  ", "no  ").with_style(Style::new(Color::Red)),
            Status::Unknown => {
                paintalt("？ ", "??? ").with_style(Style::new(Color::Magenta).bold())
            }
        }
    }

    pub fn downgrade_fatal(self) -> Self {
        match self {
            Status::Fatal => Status::Unsupported,
            v => v,
        }
    }
}

impl Default for Status {
    fn default() -> Status {
        Status::Unknown
    }
}

impl std::ops::BitAnd for Status {
    type Output = Status;

    fn bitand(self, other: Status) -> Status {
        match (self, other) {
            (_, Status::Fatal) => Status::Fatal,
            (Status::Fatal, _) => Status::Fatal,
            (_, Status::Unknown) => Status::Unknown,
            (Status::Unknown, _) => Status::Unknown,
            (_, Status::Supported) => Status::Supported,
            (Status::Supported, _) => Status::Supported,
            (Status::Unsupported, Status::Unsupported) => Status::Unsupported,
        }
    }
}

impl std::ops::BitOr for Status {
    type Output = Status;

    fn bitor(self, other: Status) -> Status {
        match (self, other) {
            (_, Status::Supported) => Status::Supported,
            (Status::Supported, _) => Status::Supported,
            (_, Status::Unknown) => Status::Unknown,
            (Status::Unknown, _) => Status::Unknown,
            _ => Status::Fatal,
        }
    }
}

pub trait StatusConv {
    fn as_opt(self) -> Status;
    fn as_req(self) -> Status;
}

impl StatusConv for bool {
    fn as_opt(self) -> Status {
        if self {
            Status::Supported
        } else {
            Status::Unsupported
        }
    }

    fn as_req(self) -> Status {
        if self {
            Status::Supported
        } else {
            Status::Fatal
        }
    }
}

impl StatusConv for Option<bool> {
    fn as_opt(self) -> Status {
        match self {
            Some(true) => Status::Supported,
            Some(false) => Status::Unsupported,
            None => Status::Unknown,
        }
    }

    fn as_req(self) -> Status {
        match self {
            Some(true) => Status::Supported,
            Some(false) => Status::Fatal,
            None => Status::Unknown,
        }
    }
}
