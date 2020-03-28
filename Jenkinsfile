
def installRust = '''#!/bin/bash -e
wget https://sh.rustup.rs -O rustup.sh
chmod +x rustup.sh
./rustup.sh -y --default-toolchain nightly
source $HOME/.cargo/env

rustup default nightly
rustup update nightly
rustup target add x86_64-fortanix-unknown-sgx

mkdir -p $HOME/.cargo
cat > $HOME/.cargo/config << EOF
[target.x86_64-fortanix-unknown-sgx]
runner = "ftxsgx-runner-cargo"
EOF

rustup show
'''

def installFortanixSgxTools = '''#!/bin/bash -e
source $HOME/.cargo/env
cd rust-sgx
git branch
git log -n 1
cargo clean
cargo install --path fortanix-sgx-tools --locked --debug
'''

def runRustTests = '''#!/bin/bash -e
unset SUDO_USER
source $HOME/.cargo/env
export X86_FORTANIX_SGX_LIBS=$(dirname $(dirname $(rustup which rustc)))/lib/rustlib/x86_64-fortanix-unknown-sgx/lib
cd rust
rm -rf build/x86_64-unknown-linux-gnu/test
./configure --enable-lld --disable-rpath
./x.py test --stage=1 --target=x86_64-fortanix-unknown-sgx src/libstd --no-doc 2>&1
./x.py test --stage=1 --target=x86_64-fortanix-unknown-sgx src/test/run-make --no-doc 2>&1
'''

node( 'rust-sgx-ci' ){

    stage("Checkout rust"){
        checkout([
            $class: 'GitSCM',
            branches: [[name: '*/master']],
            doGenerateSubmoduleConfigurations: false,
            extensions: [
                [$class: 'PruneStaleBranch'],
                [$class: 'RelativeTargetDirectory', relativeTargetDir: 'rust'],
                [
                    $class: 'SubmoduleOption',
                    disableSubmodules: false,
                    parentCredentials: false,
                    recursiveSubmodules: true,
                    reference: '',
                    trackingSubmodules: false
                ]
            ],
            submoduleCfg: [],
            userRemoteConfigs: [[url: 'https://github.com/rust-lang/rust']]
        ])
    }

    stage("Checkout rust-sgx"){
        checkout([
            $class: 'GitSCM',
            branches: [[name: env.BRANCH_NAME ?: "*/master"]],
            doGenerateSubmoduleConfigurations: false,
            extensions: [
                [$class: 'PruneStaleBranch'],
                [$class: 'CleanBeforeCheckout'],
                [$class: 'CleanCheckout'],
                [$class: 'RelativeTargetDirectory', relativeTargetDir: 'rust-sgx'],
            ],
            submoduleCfg: [],
            userRemoteConfigs: [[url: 'https://github.com/fortanix/rust-sgx']]
        ])
    }

    stage("Install Rust"){
        timestamps { sh installRust }
    }

    stage("Install Fortanix SGX Tools"){
        timestamps { sh installFortanixSgxTools }
    }

    stage("Run Rust Tests"){
        timestamps { sh runRustTests }
    }

    stage("Update GitHub Status"){
        if (currentBuild.currentResult == 'SUCCESS') {
            echo 'The build was successful!'
        } else {
            echo 'The build failed :('
        }
    }
}
