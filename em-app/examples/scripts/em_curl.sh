#!/bin/bash
set -a
# Ignore this file
# Added to help debug changes
#
# Utility script to use curl instead of em-cli for the registration flow where em-cli is not available.
# This is not meant to have feature parity with em-cli, there are missing commands and there is no parameter validation.
#

function curl_raw() {
    if [[ "$curl_opts" == *"-v"* ]]; then
        curl $curl_opts -k -H "X-CSRF-Header: true" "$@"
    else
        curl $curl_opts -k -H "X-CSRF-Header: true" -fsS "$@"
    fi
}

function curl_with_user_session() {
    if [ ! -f "${token:-}" ]; then
        echo "Script error, token must be a cookie store file: ${token:-}"
        exit 1
    fi
        
    curl_raw -b "$token" -c "$token" "$@"
}

function em-user() {
    case $1 in
        login)
            basic_token=$(echo -n "$3:$4" | base64 -w 0)
            em_url=$2

            export token=$(mktemp -t "cookiejar.XXXXX")
            curl_raw -H "Content-Type: application/json" -H "Authorization: Basic $basic_token" -b "$token" -c "$token" -d '' "$em_url/v1/sys/auth" > /dev/null
            
            echo "Logged in"
            echo "    export token=$token"
            echo "    export em_url=$em_url"
            ;;
        refresh)
            curl_with_user_session -X POST -H "Content-Type: application/json" -d '' "$em_url/v1/sys/session/refresh" > /dev/null
            ;;
        create)
            em_url=$2
            curl_raw -d '{"user_email": "'"$3"'", "user_password": "'"$4"'", "recaptcha_response": "random"}' $em_url/v1/users | jq -aM .
            ;;
        myinfo)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/user" | jq -aM .
            ;;
        invite)
            curl_with_user_session -X POST -H "Content-Type: application/json" -d '{ "user_email": "'"$2"'", "roles":[ "'"$3"'" ] }' "$em_url/v1/users/invite" | jq -aM .
            ;;
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/users" | jq -aM .
            ;;
        accept-invite)
            curl_with_user_session -X POST -H "Content-Type: application/json" -d '{ "accepts":[ "'"$2"'" ] }' "$em_url/v1/users/process_invite" | jq -aM .
            ;;
        
        *)
            echo "Unsupported command: em-curl user $*" >&2
            exit 1
            ;;
    esac
}

function em-account() {
    case $1 in
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/accounts" | jq -aM .
            ;;
        create)
            shift
            enforcement="$1"
            shift
            curl_with_user_session -X POST -H "Content-Type: application/json" -d '{ "name": "'"$*"'", "custom_logo": "", "node_enrollment": { "attestation_enforcement_disabled_insecure": '$enforcement' } }' "$em_url/v1/accounts" | jq -aM .
            ;;
        select)
            curl_with_user_session -X POST -H "Content-Type: application/json" -d '' "$em_url/v1/sys/session/select_account/$2" >/dev/null
            echo "Account selected"
            ;;
        *)
            echo "Unsupported command: em-curl account $*" >&2
            exit 1
            ;;
    esac                        
}

function em-build() {
    case $1 in
        parse-sigstruct)
            local sigstruct=$2
            local mrenclave=$(od -A none -t x1 --read-bytes=32 -j 960 -w32 $sigstruct | tr -d ' ')
            local mrsigner=$(dd if=$sigstruct bs=1 skip=128 count=384 status=none | sha256sum | awk '{print $1}')
            local isvprodid=$(od --endian=little --read-bytes=2 -j 1024 -s $sigstruct | awk '{print $2}')
            local isvsvn=$(od --endian=little --read-bytes=2 -j 1026 -s $sigstruct | awk '{print $2}')
            echo '{ "mrenclave":"'$mrenclave'","mrsigner":"'$mrsigner'","isvprodid":"'$isvprodid'","isvsvn":"'$isvsvn'" }'
            ;;
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/builds" | jq -aM .
            ;;
        create)
            local sigstruct=$3
            local mrenclave=$(od -A none -t x1 --read-bytes=32 -j 960 -w32 $sigstruct | tr -d ' ')
            local mrsigner=$(dd if=$sigstruct bs=1 skip=128 count=384 status=none | sha256sum | awk '{print $1}')
            local isvprodid=$(od --endian=little --read-bytes=2 -j 1024 -s $sigstruct | awk '{print $2}')
            local isvsvn=$(od --endian=little --read-bytes=2 -j 1026 -s $sigstruct | awk '{print $2}')


            if [ ! -z "$4" ]; then
                local image_name=$4
                local image_version=$5
                
                curl_with_user_session -X POST -H "Content-Type: application/json" -d '{"app_id":"'$2'","mrenclave":"'$mrenclave'","mrsigner":"'$mrsigner'","isvprodid":'$isvprodid',"isvsvn":'$isvsvn', "docker_info":{ "docker_image_name":"'"$image_name"'", "docker_version":"'"$image_version"'"} }' "$em_url/v1/builds" | jq -aM .
            else
                curl_with_user_session -X POST -H "Content-Type: application/json" -d '{"app_id":"'$2'","mrenclave":"'$mrenclave'","mrsigner":"'$mrsigner'","isvprodid":'$isvprodid',"isvsvn":'$isvsvn'}' "$em_url/v1/builds" | jq -aM .
            fi
            ;;
        create-param)
            local mrenclave=$3
            local mrsigner=$4
            local isvprodid=$5
            local isvsvn=$6

            if [ ! -z "$8" ]; then
                local image_name=$7
                local image_version=$8
                
                curl_with_user_session -X POST -H "Content-Type: application/json" -d '{"app_id":"'$2'","mrenclave":"'$mrenclave'","mrsigner":"'$mrsigner'","isvprodid":'$isvprodid',"isvsvn":'$isvsvn', "docker_info":{ "docker_image_name":"'"$image_name"'", "docker_version":"'"$image_version"'"} }' "$em_url/v1/builds" | jq -aM .
            else
                curl_with_user_session -X POST -H "Content-Type: application/json" -d '{"app_id":"'$2'","mrenclave":"'$mrenclave'","mrsigner":"'$mrsigner'","isvprodid":'$isvprodid',"isvsvn":'$isvsvn'}' "$em_url/v1/builds" | jq -aM .
            fi
            ;;
        allow-config)
            shift
            curl_with_user_session -X PATCH -H "Content-Type: application/json" -d '{ "configs":{ "'$2'": {} }}' "$em_url/v1/builds/$1" | jq -aM .
            ;;
        *)
            echo "Unsupported command: em-curl build $*" >&2
            exit 1
            ;;
    esac
}

function em-dataset() {
    case $1 in
        get)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/datasets/$2"
            ;;
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/datasets"
            ;;
        create)
            curl_with_user_session -X POST -H "Content-Type: application/json" -d @"$2" "$em_url/v1/datasets"
            ;;
        update)
            curl_with_user_session -X PATCH -H "Content-Type: application/json" -d @"$3" "$em_url/v1/datasets/$2"
            ;;
        delete)
            curl_with_user_session -X DELETE -H "Content-Type: application/json" -d '' "$em_url/v1/datasets/$2"
            ;;
        *)
            echo "Unsupported command: em-curl dataset $*" >&2
            exit 1
            ;;
    esac
}

function em-workflow-graph() {
    case $1 in
        create)
            curl_with_user_session -X POST -H "Content-Type: application/json" -d @"$2" "$em_url/v1/workflows/draft/graphs"
            ;;
        update)
            curl_with_user_session -X PUT -H "Content-Type: application/json" -d @"$3" "$em_url/v1/workflows/draft/graphs/$2"
            ;;
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/workflows/draft/graphs"
            ;;
        *)
            echo "Unsupported command: em-curl workflow $*" >&2
            exit 1
            ;;
    esac
}

function em-final-workflow() {
    case $1 in
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/workflows/final/graphs"
            ;;
        get)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/workflows/final/graphs/$2"
            ;;
        delete)
            curl_with_user_session -X DELETE -H "Content-Type: application/json" -d '' "$em_url/v1/workflows/final/graphs/$2/$3"
            ;;
        update)
            curl_with_user_session -X POST -H "Content-Type: application/json" -d @"$3" "$em_url/v1/workflows/final/graphs/$2"
            ;;
        patch)
            curl_with_user_session -X PATCH -H "Content-Type: application/json" -d @"$4" "$em_url/v1/workflows/final/graphs/$2/$3"
            ;;
        *)
            echo "Unsupported command: em-curl workflow $*" >&2
            exit 1
            ;;
    esac
}


function em-approval() {
    case $1 in
        create)
            curl_with_user_session -X POST -H "Content-Type: application/json" -d @"$2" "$em_url/v1/approval_requests" | jq -aM .
            ;;
        approve)
            curl_with_user_session -X POST -H "Content-Type: application/json" "$em_url/v1/approval_requests/$2/approve" | jq -aM .
            ;;
        get)
            curl_with_user_session -X GET -H "Content-Type: application/json" "$em_url/v1/approval_requests/$2" | jq -aM .
            ;;
        result)
            curl_with_user_session -X POST -H "Content-Type: application/json" "$em_url/v1/approval_requests/$2/result" | jq -aM .
            ;;
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/approval_requests" | jq -aM .
            ;;
        delete)
            curl_with_user_session -X DELETE -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '' "$em_url/v1/approval_requests/$2"
            ;;
        *)
            echo "Unsupported command: em-curl workflow $*" >&2
            exit 1
            ;;
    esac
}


function em-application-config() {
    case $1 in
        get)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/app_configs/$2"
            ;;
        get-runtime)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/runtime/app_configs/$2"
            ;;
        list)
            shift
            if [ ! -z "$1" ]; then
                curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/app_configs?$*"
            else
                curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/app_configs"
            fi
            ;;
        create)
            curl_with_user_session -X POST -H "Content-Type: application/json" -d @"$2" "$em_url/v1/app_configs"
            ;;
        delete)
            curl_with_user_session -X DELETE -H "Content-Type: application/json" -d '' "$em_url/v1/app_configs/$2"
            ;;
        *)
            echo "Unsupported command: em-curl workflow $*" >&2
            exit 1
            ;;
    esac
}

function em-app() {
    case $1 in
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/apps" | jq -aM .
            ;;
        create)
            local domains=$5
            domains=${domains//,/\",\"}
            curl_with_user_session -X POST -H "Content-Type: application/json" -d '{ "name": "'$2'", "input_image_name": "EDP ENCLAVE APP - 5f42a1ee280cf158490a8", "output_image_name": "EDP ENCLAVE APP - 5f42a1ee280cf158490a8", "isvprodid": '$3', "isvsvn": '$4', "mem_size": 1024, "threads": 128, "allowed_domains": [ "'$domains'" ]}' "$em_url/v1/apps" | jq -aM .
            ;;
        create-json)
            curl_with_user_session -X POST -H "Content-Type: application/json" -d @"$2" "$em_url/v1/apps" | jq -aM .
            ;;
        update)
            local app_id=$2
            shift
            shift
            case $1 in
                --allowed-domains)
                    domains=$2
                    domains=${domains//,/\",\"}
                    curl_with_user_session -X PATCH -H "Content-Type: application/json" -d '{ "allowed_domains": [ "'$domains'" ]}' "$em_url/v1/apps/$app_id" | jq -aM .
                    ;;
                *)
                    echo "Unsupported command: em-curl app update $app_id $*" >&2
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo "Unsupported command: em-curl app $*" >&2
            exit 1
            ;;
    esac

}
function em-task() {
    case $1 in
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/tasks" | jq -aM .
            ;;
        update)
            task_id=$2
            status=$3
            curl_with_user_session -X PATCH -H "Content-Type: application/json" -d '{"status": "'${status^^}'"}' "$em_url/v1/tasks/$task_id" | jq -aM .
            ;;
        *)
            echo "Unsupported command: em-curl task $*" >&2
            exit 1
            ;;
    esac
}

function em-node() {
    case $1 in
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/nodes" | jq -aM .
            ;;
        *)
            echo "Unsupported command: em-curl node $*" >&2
            exit 1
            ;;
    esac
}

function em-zone() {
    case $1 in
        list)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/zones" | jq -aM .
            ;;
        token)
            curl_with_user_session -X GET -H "Content-Type: application/json" -d '' "$em_url/v1/zones/$2/token"
            ;;
        *)
            echo "Unsupported command: em-curl zone $*" >&2
            exit 1
            ;;
    esac
}

function em-cli() {
    case "$1" in
        approval)
            shift
            em-approval $*
            ;;
        user)
            shift
            em-user $*
            ;;
        account)
            shift
            em-account $*
            ;;
        build)
            shift
            em-build $*
            ;;
        app)
            shift
            em-app $*
            ;;
        task)
            shift
            em-task $*
            ;;
        node)
            shift
            em-node $*
            ;;
        zone)
            shift
            em-zone $*
            ;;
        workflow)
            shift
            em-workflow $*
            ;;
        application-config)
            shift
            em-application-config $*
            ;;
        dataset)
            shift
            em-dataset $*
            ;;
        workflow-graph)
            shift
            em-workflow-graph $*
            ;;
        final-workflow)
            shift
            em-final-workflow $*
            ;;
        *)
            echo "Unsupported command: $*" >&2
            exit 1
            ;;
    esac
}

if [[ $_ == $0 ]]; then
    em-cli $*
fi
