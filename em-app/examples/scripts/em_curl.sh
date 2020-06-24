#
# Utility script to use curl instead of em-cli for the registration flow where em-cli is not available.
# This is not meant to have feature parity with em-cli, there are missing commands and there is no parameter validation.
# 

function em-user() {
    case $1 in
        login)
            basic_token=$(echo -n "$3:$4" | base64 -w 0)
            em_url=$2
            token=$(curl $curl_opts -fsS -H "Content-Type: application/json" -H "Authorization: Basic $basic_token" -d '' "$em_url/v1/sys/auth" | jq -r '.access_token')

            echo "Logged in"
            echo "    export token=$token"
            echo "    export em_url=$em_url"
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
            curl $curl_opts -fsS -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '' "$em_url/v1/accounts" | jq .
            ;;
        create)
            curl $curl_opts -fsS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d "{ \"name\": \"$2\", \"custom_logo\": \"\" }" "$em_url/v1/accounts" | jq .
            ;;
        select)
            curl $curl_opts -fsS -k -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '' "$em_url/v1/accounts/select_account/$2"
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
            curl $curl_opts -fsS -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '' "$em_url/v1/builds" | jq .
            ;;
        create)
            local sigstruct=$3
            local mrenclave=$(od -A none -t x1 --read-bytes=32 -j 960 -w32 $sigstruct | tr -d ' ')
            local mrsigner=$(dd if=$sigstruct bs=1 skip=128 count=384 status=none | sha256sum | awk '{print $1}')
            local isvprodid=$(od --endian=little --read-bytes=2 -j 1024 -s $sigstruct | awk '{print $2}')
            local isvsvn=$(od --endian=little --read-bytes=2 -j 1026 -s $sigstruct | awk '{print $2}')

            curl  $curl_opts -fsS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '{"app_id":"'$2'","mrenclave":"'$mrenclave'","mrsigner":"'$mrsigner'","isvprodid":'$isvprodid',"isvsvn":'$isvsvn'}' "$em_url/v1/builds" | jq .
            ;;
        *)
            echo "Unsupported command: em-curl build $*" >&2
            exit 1
            ;;
    esac
}

function em-app() {
    case $1 in
        list)
            curl $curl_opts -fsS -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '' "$em_url/v1/apps" | jq .
            ;;
        create)
            local domains=$5
            domains=${domains//,/\",\"}
            curl $curl_opts -fsS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '{ "name": "'$2'", "input_image_name": "EDP ENCLAVE APP - 5f42a1ee280cf158490a8", "output_image_name": "EDP ENCLAVE APP - 5f42a1ee280cf158490a8", "isvprodid": '$3', "isvsvn": '$4', "mem_size": 1024, "threads": 128, "allowed_domains": [ "'$domains'" ]}' "$em_url/v1/apps" | jq .
            ;;
        update)
            local app_id=$2
            shift
            shift
            case $1 in
                --allowed-domains)
                    domains=$2
                    domains=${domains//,/\",\"}
                    curl $curl_opts -fsS -X PATCH -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '{ "allowed_domains": [ "'$domains'" ]}' "$em_url/v1/apps/$app_id" | jq .
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
            curl $curl_opts -fsS -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '' "$em_url/v1/tasks" | jq .
            ;;
        update)
            task_id=$2
            status=$3
            curl $curl_opts -fsS -X PATCH -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '{"status": "'${status^^}'"}' "$em_url/v1/tasks/$task_id" | jq .
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
            curl $curl_opts -fsS -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '' "$em_url/v1/nodes" | jq .
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
            curl $curl_opts -fsS -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '' "$em_url/v1/zones" | jq .
            ;;
        *)
            echo "Unsupported command: em-curl zone $*" >&2
            exit 1
            ;;
    esac
}

function em-cli() {
    case "$1" in
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
        *)
            echo "Unsupported command: $*" >&2
            exit 1
            ;;
    esac            
}

if [[ $_ == $0 ]]; then
    em-cli $*
fi
