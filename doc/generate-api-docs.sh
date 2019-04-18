#!/bin/bash -e

cd "$(readlink -f "$(dirname "$0")/..")"

rm -rf target/doc

# Generate docs for core/alloc/std (x86_64-fortanix-unknown-sgx target)
if [ -v RUST_DIR ]; then
    PATCH="$(readlink -f doc/rust-std-edp-doc.patch)"
    pushd $RUST_DIR
    COMMIT=$(rustc --version -v|sed -n 's/^commit-hash: //p')
    git checkout $COMMIT
    git reset --hard $COMMIT
    git submodule update --init --recursive
    git apply < $PATCH
    rm -rf target/x86_64-fortanix-unknown-sgx/doc
    cargo doc --target x86_64-fortanix-unknown-sgx --no-deps -p core
    cargo doc --target x86_64-fortanix-unknown-sgx --no-deps -p alloc
    cargo doc --target x86_64-fortanix-unknown-sgx --no-deps -p std
    popd
    mkdir -p target
    cp -r $RUST_DIR/target/x86_64-fortanix-unknown-sgx/doc target
else
    echo 'Skipping `std` docs, set RUST_DIR if you want to generate those'
fi

# Generate docs for all libraries in the workspace
LIBS=$(
    cargo metadata --format-version 1 \
    | jq -r '
          .packages
        | .[]
        | select(.source == null)
        | select(.targets[].kind[] == "lib")
        | .name'
)

# Sort so that dependencies are built first, enabling inter-crate links
LIBS_SORTED=$(
    cargo metadata --format-version 1 \
    | jq -r '
          .packages
        | .[]
        | select(.source == null)
        | select(.targets[].kind[] == "lib")
        | [ .dependencies[].name + " " + .name ]
        | .[]' \
    | tsort \
    | egrep '^'$(echo $LIBS|sed 's/ /|/g')'$'
)

dependencies=''

for LIB in $LIBS_SORTED; do
    cd $LIB
    version=$(git tag --sort=taggerdate | grep $LIB'_' | tail -n1 | cut -d'_' -f2 | cut -d'v' -f2)
    dependency=$LIB' = { version = "'$version'"'
    features="$(cargo read-manifest|jq -c '.metadata.docs.rs.features')"
    if [ $features != 'null' ]; then
        dependency=$dependency', features = '$features
    fi
    dependency=$dependency' }'
    dependencies=$dependencies$dependency$'\n'
    cd -
done

pushd $WORKSPACE
cargo new foo
cd foo
echo "$dependencies" >> Cargo.toml
cargo doc
popd

for LIB in $LIBS_SORTED; do
    cp -r $WORKSPACE/foo/target/doc/$LIB target/doc
done
