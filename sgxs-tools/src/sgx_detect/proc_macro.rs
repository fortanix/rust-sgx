#![cfg_attr(feature = "docs", doc(hidden))]

#[cfg(feature = "docs")]
compile_error!("Should not be documented on docs.rs");

#[macro_use]
extern crate lazy_static;
extern crate proc_macro;

use std::collections::{BTreeMap, BTreeSet};
use std::iter;
use std::result::Result as StdResult;
use std::sync::Mutex;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::parse::{ParseStream, Parser};
use syn::*;

/// Transform a `struct` definition into two new structs.
///
/// The outer struct (with the same identifier as the original struct) will
/// contain a single optional field of the inner struct. The inner struct will
/// contain all the fields of the original definition.
///
/// Derivations from this crate will be preserved on the outer struct and
/// stripped from the inner struct. All other derivations and attributes will
/// be present on both structs. `#[derive(Default)]` will be added on the outer
/// struct if it is not already specified.
///
/// # Examples
/// ```ignore
/// #[optional_inner]
/// #[derive(Clone, Print)]
/// struct MyStruct {
///     value: i32
/// }
/// ```
///
/// Will become:
///
/// ```ignore
/// #[derive(Clone, Print, Default)]
/// struct MyStruct {
///     inner: Option<MyStructInner>
/// }
///
/// #[derive(Clone)]
/// struct MyStructInner {
///     value: i32
/// }
/// ```
#[proc_macro_attribute]
pub fn optional_inner(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    fn optional_inner_inner(mut outer: ItemStruct) -> syn::Result<TokenStream> {
        type DeriveList = punctuated::Punctuated<Ident, Token![,]>;

        let mut inner = outer.clone();

        // =====
        // Inner
        // =====
        inner.ident = Ident::new(&(inner.ident.to_string() + "Inner"), inner.ident.span());

        let mut already_has_derive_debug = false;

        // Adjust inner derive list
        for attr in &mut inner.attrs {
            if attr.path.is_ident("derive") {
                let meta = (|stream: ParseStream| {
                    let content;
                    parenthesized!(content in stream);
                    DeriveList::parse_terminated(&content)
                })
                .parse2(attr.tts.clone())?;
                let meta = meta
                    .into_pairs()
                    .map(punctuated::Pair::into_value)
                    .filter(|ident| match ident.to_string().as_str() {
                        "MaybeSupport" | "DebugSupport" | "Print" | "Update" => false,
                        "Default" => {
                            already_has_derive_debug = true;
                            true
                        },
                        _ => true,
                    })
                    .collect::<DeriveList>();
                attr.tts = quote! { ( #meta ) };
            }
        }

        // =====
        // Outer
        // =====
        let ident = &inner.ident;
        if !already_has_derive_debug {
            outer.attrs.extend(Attribute::parse_outer.parse2(quote! { #[derive(Default)] })?);
        }
        outer.fields = Fields::Named(parse2(quote! {
            {
                inner: Option<#ident>
            }
        })?);

        let mut toks = outer.into_token_stream();
        inner.to_tokens(&mut toks);
        Ok(toks)
    }

    assert!(attr.is_empty());

    match optional_inner_inner(parse_macro_input!(item as ItemStruct)) {
        Ok(ts) => ts,
        Err(e) => e.to_compile_error(),
    }
    .into()
}

type DependencyMap = BTreeMap<String, BTreeSet<String>>;

lazy_static! {
    static ref DEPS: Mutex<Option<DependencyMap>> = Mutex::new(Some(Default::default()));
}

/// Record an implementation of `impl Dependency`.
///
/// This records the types `T` and `U` in an `impl Dependency<T> for U` item.
/// See the [`define_dependencies!`] macro for more information.
///
/// [`define_dependencies!`]: macro.define_dependencies.html
#[proc_macro_attribute]
pub fn dependency(
    attr: proc_macro::TokenStream,
    mut item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    assert!(attr.is_empty());

    fn check_impl(impl_: ItemImpl) -> StdResult<(Type, Type), Box<dyn ToTokens>> {
        use self::GenericArgument::Type as GaType;

        let mut trait_ = match impl_.trait_ {
            Some(trait_) => trait_,
            _ => return Err(Box::new(impl_)),
        };

        let PathSegment { ident, arguments } = match trait_.1.segments.last() {
            Some(punctuated::Pair::End(_)) => trait_.1.segments.pop().unwrap().into_value(),
            _ => return Err(Box::new(trait_.1)),
        };

        if ident.to_string() != "Dependency" {
            return Err(Box::new(ident));
        }
        let genargs = match arguments {
            PathArguments::AngleBracketed(genargs) => genargs,
            _ => return Err(Box::new(arguments)),
        };

        let typearg = match genargs
            .args
            .iter()
            .filter(|ga| match *ga {
                GaType(_) => true,
                _ => false,
            })
            .count()
        {
            1 => genargs
                .args
                .into_iter()
                .filter_map(|ga| match ga {
                    GaType(ty) => Some(ty),
                    _ => None,
                })
                .next()
                .unwrap(),
            _ => return Err(Box::new(genargs)),
        };

        Ok((typearg, *impl_.self_ty))
    }

    let item2 = item.clone();
    let impl_ = parse_macro_input!(item2 as ItemImpl);
    let (dependency, dependent) = match check_impl(impl_) {
        Ok(v) => v,
        Err(e) => {
            return Error::new_spanned(e, "expected `impl Dependency<...> for ...`")
                .to_compile_error()
                .into()
        }
    };

    item.extend(iter::once(proc_macro::TokenStream::from(
        (quote! {
            impl __missing_dependency_attribute__<#dependency> for #dependent {}
        })
        .into_token_stream(),
    )));

    let dependency = dependency.into_token_stream().to_string();
    let dependent = dependent.into_token_stream().to_string();

    let mut panic = None;
    if let Some(map) = DEPS.lock().unwrap().as_mut() {
        if !map
            .entry(dependency.clone())
            .or_default()
            .insert(dependent.clone())
        {
            panic = Some(format!(
                "Duplicate dependency: {} on {}",
                dependent, dependency
            ))
        }
    } else {
        panic = Some("Adding dependencies after `define_dependencies!` invocation".into());
    }
    if let Some(msg) = panic {
        panic!(msg);
    }

    item
}

/// Define the `const DEPENDENCIES` array.
///
/// This macro should be invoked as follows after all items marked
/// `#[dependency]`:
/// ```ignore
/// define_dependencies!($path1, $type1, $path2, $type2);
/// ```
/// This will define an array of all types in dependencies marked with 
/// `#[dependency]`. The type of the array elements will be `(fn() -> TypeId, 
/// $type1, fn() -> TypeId, $type1, $type2)`. Each element in the array will 
/// describe an edge in the dependency graph. For an item `impl Dependency<T> 
/// for U`, the tuple elements will be as follows:
///
/// * [`TypeId`] of the dependency `T`,
/// * `$path1::<T>`, which should be a value of type `$type1`,
/// * [`TypeId`] of the dependent `U`,
/// * `$path1::<U>`, which should be a value of type `$type1`,
/// * `$path2::<T, U>`, which should be a value of type `$type2`.
///
/// [`TypeId`]: https://doc.rust-lang.org/std/any/struct.TypeId.html
#[proc_macro]
pub fn define_dependencies(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let (path1, ty1, path2, ty2) = match (|stream: ParseStream| {
        let path1: TypePath = stream.parse()?;
        let _: Token![,] = stream.parse()?;
        let ty1: Type = stream.parse()?;
        let _: Token![,] = stream.parse()?;
        let path2: TypePath = stream.parse()?;
        let _: Token![,] = stream.parse()?;
        let ty2: Type = stream.parse()?;
        Ok((path1, ty1, path2, ty2))
    })
    .parse(input)
    {
        Err(e) => return e.to_compile_error().into(),
        Ok(v) => v,
    };

    let map = DEPS.lock().unwrap().take();
    // drop DEPS lock
    if let Some(map) = map {
        let typeid = &quote!(::std::any::TypeId);
        let path1 = &path1;
        let path2 = &path2;
        let elems = map.iter().flat_map(|(k, vs)| {
            vs.iter().map(move |v| {
                let k: TokenStream = k.parse().unwrap();
                let v: TokenStream = v.parse().unwrap();
                quote!((#typeid::of::<#k>, #path1::<#k>, #typeid::of::<#v>, #path1::<#v>, #path2::<#k, #v>))
            })
        });

        quote!(
            const DEPENDENCIES: &[(
                fn() -> #typeid,
                #ty1,
                fn() -> #typeid,
                #ty1,
                #ty2
            )] = &[#(#elems),*];
        )
        .into()
    } else {
        panic!("`define_dependencies!` invoked twice");
    }
}

/// Implements `DebugSupport`.
#[proc_macro_derive(DebugSupport)]
pub fn derive_debug_support(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(item as DeriveInput);

    quote!(impl DebugSupport for #ident {}).into()
}

/// Implements `Print`.
///
/// This will generate the following implementation for `try_supported`:
/// ```ignore
/// fn try_supported(&self) -> Option<Status> {
///     None
/// }
/// ```
#[proc_macro_derive(Print)]
pub fn derive_print(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(item as DeriveInput);

    quote!(impl Print for #ident {
        fn try_supported(&self) -> Option<Status> {
            None
        }
    })
    .into()
}

/// Implements `Update`.
#[proc_macro_derive(Update)]
pub fn derive_update(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(item as DeriveInput);

    quote!(impl Update for #ident {}).into()
}
