#!/usr/bin/env bash

#Absoulte Path For Binaries
SYSTEMCTL=$(command -v systemctl)
DOCKER=$(command -v docker)
PODMAN=$(command -v podman)
CURL=$(command -v curl)
OPENSSL=$(command -v openssl)
LOGINCTL=$(command -v loginctl)
RM=$(command -v rm)
SUDO=$(command -v sudo)
TEE=$(command -v tee)
MV=$(command -v mv)
APTGET=$(command -v apt-get)
YUM=$(command -v yum)


# Variables
ECR_URL="public.ecr.aws/moveworks/agent:"
AGENT_VERSION=""
LATEST_AGENT_VERSION=2.10.3
NON_ROOT_USERNAME=""
AGENT_COUNT=1 # This variable is used to store the number of agents running default 1
AGENT_TO_BE_STOPPED=0 # This variable is used to store the number of agents to be stopped when upgrading the agent
AGENT_STOPPED=0 # This variable is used to store the number of agents stopped
AGENT_TO_START=1 # This variable is used to store the number of agents to start default 1
IMAGE_DIR="/home/moveworks/agent"
DOCKER_VERSION=20.10.0
DOCKER_VERSION_LATEST=25.0.3
PODMAN_VERSION=3.4.4
SYSTEM_TYPE=""
OS_VERSION=""
IS_UPGRADE=false
docker="docker"
podman="podman"

# If NON_ROOT_USERNAME is not set as env variable empty, default it to the whoami
if [[ -z "$NON_ROOT_USERNAME" ]]; then
    NON_ROOT_USERNAME=$(whoami)
fi

echo "Setting up agent with user $NON_ROOT_USERNAME"

if [ ! -d "moveworks" ]; then
  mkdir moveworks || {
    printErr "Failed to create directory 'moveworks'. Please check permissions." >&2
    exit 1
  }
fi
cd moveworks || {
  printErr "Failed to move to directory 'moveworks'. Please check and rerun" >&2
  exit 1
}

AGENT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_TEMP_DIR="/tmp/vars"
AGENT_TEMP_FILE="$AGENT_TEMP_DIR/moveworks_agent.txt"
readonly AGENT_GROUP_ID=17540
readonly DIRECTORIES="conf certs logs ."
readonly INFO_LEVEL="INFO"
readonly DEBUG_LEVEL="DEBUG"
readonly MOVEWORKS_IMAGE="moveworks_agent:latest"
# Default log level, can be overridden by passing the --debug flag
LOG_LEVEL="${INFO_LEVEL}"


# Colors
readonly RED="\e[31m"
readonly RESET="\e[0m"

function set_configure_options() {
    readonly CONFIGURE_AGENT_COMMON_OPTIONS="run --rm -ti -e MODE=configure -v ${AGENT_DIR}/conf:${IMAGE_DIR}/conf -v ${AGENT_DIR}/certs:${IMAGE_DIR}/certs -v ${AGENT_DIR}:${IMAGE_DIR}/scripts "
    readonly CONFIGURE_PODMAN_OPTIONS="run -u 0 --privileged --rm -ti -e MODE=configure -v ${AGENT_DIR}/conf:${IMAGE_DIR}/conf -v ${AGENT_DIR}/certs:${IMAGE_DIR}/certs -v ${AGENT_DIR}:${IMAGE_DIR}/scripts "

    readonly PODMAN_CONFIGURE_AGENT="$PODMAN $CONFIGURE_PODMAN_OPTIONS"
    readonly DOCKER_CONFIGURE_AGENT="$DOCKER $CONFIGURE_AGENT_COMMON_OPTIONS"
}
# Function to display usage documentation
function show_usage() {
    echo "Description: Helper script to setup, start and stop the moveworks agent."
    echo "Options:"
    echo  " --docker              Install the agent using docker container.optional arguments: --host-network or --fips, if not provided agent is started with default options."
    echo  " --podman              Install the agent using podman container.optional arguments: --host-network or --fips, if not provided agent is started with default options."
    echo "  -u, --upgrade         Upgrade the agent to latest version. optional arguments: --host-network or --fips, if not provided agent is started with default options."
    echo "  -h, --help            Display this usage documentation."
    echo "  -i, --init            Initialize the agent. This should be run once during the initial setup of the agent."
    echo "  -c, --configure       Configure the agent. This should be run after the agent is initialized and before starting the agent."
    echo "  -s, --start           Start the agent, optional arguments: --host-network or --fips, if not provided agent is started with default options."
    echo "  -t, --stop            Stop all running agents."
    echo "  -p, --permissions     Fix user permissions of agent folder. This should be executed with sudo permissions."
    echo "  -v, --validate        Validate the agent machine setup."
    echo "  -f, --fetch           Fetch LDAP certificate. This requires openssl and sudo permissions"
    echo "  -d, --debug           Start the agent in debug mode, optional arguments: --host-network or --fips, if not provided agent is started with default options."
}

# Function to check the container runtime
function check_container_runtime() {
    if command -v podman &> /dev/null; then
        echo "$podman"
    elif command -v docker &> /dev/null; then
        echo "$docker"
    else
        echo "none"
    fi
}
CONTAINER_RUNTIME=$(check_container_runtime)

function check_root() {
    # Check if script is run with superuser (root) permissions
    if [[ $EUID -ne 0 ]]; then
      printErr "This script must be run with sudo - please rerun as root."
      exit 1
    fi
}

# Function to check if a command is available
function command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to compare decimal`
function compare_values() {
    local num1="$1"
    local num2="$2"
    local operator="$3"

    case $operator in
        "gt")
            if (( $(awk -v num1="$num1" -v num2="$num2" 'BEGIN {print(num1>num2)}') )); then
                echo 1
            else
                echo 0
            fi
            ;;
        "ge")
            if (( $(awk -v num1="$num1" -v num2="$num2" 'BEGIN {print(num1>=num2)}') )); then
                echo 1
            else
                echo 0
            fi
            ;;
        "lt")
            if (( $(awk -v num1="$num1" -v num2="$num2" 'BEGIN {print(num1<num2)}') )); then
                echo 1
            else
                echo 0
            fi
            ;;
        "le")
            if (( $(awk -v num1="$num1" -v num2="$num2" 'BEGIN {print(num1<=num2)}') )); then
                echo 1
            else
                echo 0
            fi
            ;;
        *) echo "Invalid comparison operator"; exit 1 ;;
    esac
}

function docker_installed_version() {
  if command_exists docker; then
    version=$($DOCKER version --format '{{.Client.Version}}')
    echo "$version"
  else
    echo "not installed"
  fi
}

function podman_installed_version() {
  if command_exists podman; then
    version=$($PODMAN version --format '{{.Client.Version}}')
    echo "$version"
  else
    echo "not installed"
  fi
}

#this function is run with sudo permissions to ensure proper setup of permissions.
function fix_permissions() {
    echo "Fixing permissions"

    # ensure the proper permissions for all files in the agent directory
    if [ "$CONTAINER_RUNTIME" == "$podman" ]; then
        $SUDO chown -R "$(id -u "$NON_ROOT_USERNAME")":$AGENT_GROUP_ID "$AGENT_DIR"
    else
        chown -R :"$AGENT_GROUP_ID" "$AGENT_DIR"
    fi
    chmod -R ug+rwx "$AGENT_DIR"
    chmod g+s "$AGENT_DIR"
}

# setup pre-requisites for agent.
# this function is run once during the initial setup of the agent.
function init() {
    echo "Initializing agent"

    for folder in $DIRECTORIES; do
        if [ ! -d "$AGENT_DIR/$folder" ]; then
            echo "Creating $AGENT_DIR/$folder"
            $SUDO mkdir "$AGENT_DIR/$folder"
        fi
    done

    # create empty agent_config.yml file
    $SUDO touch "$AGENT_DIR/conf/agent_config.yml"

    # rename the image tag
    rename
}

# configure agent
function configure() {
    echo "Configuring agent"
    set_configure_options
    if [ "$CONTAINER_RUNTIME" == "none" ]; then
        printErr "No container runtime found. Please install docker or podman."
        exit 1
    elif [ "$CONTAINER_RUNTIME" == "$docker" ]; then
        $DOCKER_CONFIGURE_AGENT $MOVEWORKS_IMAGE
    elif [ "$CONTAINER_RUNTIME" == "$podman" ]; then
       $PODMAN_CONFIGURE_AGENT $MOVEWORKS_IMAGE
    fi

}

# set COMMON_OPTIONS based log level
function set_common_options() {
  readonly START_AGENT_COMMON_OPTIONS="run -d --read-only --security-opt=no-new-privileges --restart=unless-stopped --log-opt max-size=10m --log-opt max-file=5 -e LOG_LEVEL=${LOG_LEVEL} -v ${AGENT_DIR}/conf:${IMAGE_DIR}/conf -v ${AGENT_DIR}/certs:${IMAGE_DIR}/certs -v ${AGENT_DIR}/logs:/var/log/moveworks -v ${AGENT_DIR}:${IMAGE_DIR}/scripts "
  readonly START_PODMAN_OPTIONS="run -u 0 --privileged -d --read-only --security-opt=no-new-privileges --restart=unless-stopped --log-opt max-size=10m --log-opt max-file=5 -e LOG_LEVEL=${LOG_LEVEL} -v ${AGENT_DIR}/conf:${IMAGE_DIR}/conf -v ${AGENT_DIR}/certs:${IMAGE_DIR}/certs -v ${AGENT_DIR}/logs:/var/log/moveworks -v ${AGENT_DIR}:${IMAGE_DIR}/scripts "

  readonly PODMAN_START_AGENT="$PODMAN $START_PODMAN_OPTIONS"
  readonly DOCKER_START_AGENT="$DOCKER $START_AGENT_COMMON_OPTIONS"
  readonly DOCKER_START_AGENT_HOST_NETWORK="$DOCKER $START_AGENT_COMMON_OPTIONS --net=host"
  readonly DOCKER_START_AGENT_FIPS="$DOCKER $START_AGENT_COMMON_OPTIONS -e BORINGCRYPTO=true"
}

# Function to print error messages
function printErr() {
    printf "[ERROR] $RED%s$RESET\n" "$1"
}

## check if required binaries are installed, else prompted to install
commands=("systemctl" "curl" "openssl"
          "loginctl" "rm" "sudo" "tee" "mv" )

for cmd in "${commands[@]}"; do
  if ! [ -x "$(command -v "$cmd")" ]; then
    printErr "Error: $cmd is not installed."
    printErr "Please install it and run the script again."
    exit 1
  fi
done


# Function to check the folder ownership
function check_folder_ownership() {
    folder_path="$1"

    # Check if the folder exists
    if [ ! -d "$folder_path" ]; then
        printErr "Folder '$folder_path' does not exist."
        exit 1
    fi

    # Get the UID and GID of the folder owner using stat command
    folder_owner_uid=$(stat -c "%u" "$folder_path")
    folder_owner_gid=$(stat -c "%g" "$folder_path")

    # Get the UID of the current user
    current_user_uid=$UID

    # Check if the folder is owned by the current user
    if [ "$folder_owner_uid" != "$current_user_uid" ]; then
        printErr "The folder '$folder_path' is not owned by the current user."
        exit 1
    fi

    if [ "$folder_owner_gid" != "$AGENT_GROUP_ID" ]; then
        printErr "The folder '$folder_path' is not owned by the agent group."
        exit 1
    fi
}

# check if the moveworks URL is reachable
function check_moveworks_connectivity () {
  if $CURL -Is "${MWURL}" &> /dev/null; then
    echo "Moveworks is reachable"
  else
    printErr "Moveworks is not reachable"
    exit 1
  fi
}

# check if the required package is installed, set the CMD variable to the package name
function check_if_installed() {
  CMD=$1
  if ! command -v "$CMD" &> /dev/null; then
    printErr "$CMD is not installed, please install the required package"
    exit 1
  fi
  echo "$CMD is installed"
}

# Function to check the distribution and set SYSTEM_TYPE and OS_VERSION variable
function check_Distribution() {
  if [ -f "/etc/os-release" ]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    case $ID in
      debian*)
        SYSTEM_TYPE="debian"
        ;;
      ubuntu*)
        SYSTEM_TYPE="ubuntu"
        OS_VERSION=$(echo "$VERSION_ID" | tr -d '"')
        ;;
      rhel*)
        SYSTEM_TYPE="rhel"
        OS_VERSION="$VERSION_ID"
        ;;
      centos**)
        SYSTEM_TYPE="centos"
        ;;
      amzn*)
        SYSTEM_TYPE="amzn"
        ;;
      *)
        SYSTEM_TYPE="unsupported"
        ;;
    esac
  else
    SYSTEM_TYPE="unsupported"
    exit 1
  fi
}

# check if the OS version is supported
function validate_os_version() {
   check_Distribution
    # Check if OS version is greater than or 8.x for RHEL-based Linux, CentOS, or Ubuntu 16.x or higher
    if [[ "$SYSTEM_TYPE" == "rhel" || "$SYSTEM_TYPE" == "centos" ]]; then
        if (( $(compare_values "$OS_VERSION" "8" "ge") )); then
            printf "\t%s\n" "$SYSTEM_TYPE version is 8 or greater."
        else
            printErr "$SYSTEM_TYPE version is less than 8."
            exit 1
        fi
    elif [ "$SYSTEM_TYPE" = "ubuntu" ] && (( $(compare_values "$OS_VERSION" "16" "ge") ));   then
        printf "\t%s\n" "Ubuntu version is 16.x or higher."
    else
        printErr "OS version should be RHEL 8 or higher, CentOS 8 or higher, or Ubuntu 16.x or higher."
        exit 1
    fi

}

# function to validate user lingering
function validate_lingering() {
  if $LOGINCTL show-user "$1" -p Linger | cut -d= -f2  | grep -q "yes"; then
    return 0
  else
    return 1
  fi
}


# validate the agent machine setup
function validate() {

  echo "Validating operating system version"
  validate_os_version

  echo "Validating required packages"
  result=$(check_container_runtime)
  if [ "$result" == "none" ]; then
    echo "No container runtime found. Please install docker or podman."
    exit 1
  fi

  echo "Validating folder ownership"
  for folder in $DIRECTORIES; do
    check_folder_ownership "$folder"
  done

  echo "Validating user lingering"
  if [ "$NON_ROOT_USERNAME" != "root" ] ; then
    if ! (validate_lingering "$NON_ROOT_USERNAME"); then
      printErr "User lingering is not enabled for $NON_ROOT_USERNAME"
      exit 1
    fi
  fi

  echo "Connecting to Moveworks"
  read -rp "Enter the Moveworks URL: " MWURL
  check_moveworks_connectivity

}

# fetch ldap certificate
function fetch_ldap_certificate() {
  echo "Fetching LDAP certificate"
  read -rp "Enter the LDAP URL: " LDAPURL
  $OPENSSL s_client -connect "$LDAPURL" -showcerts </dev/null 2>/dev/null | $OPENSSL x509 -outform PEM | $SUDO "$TEE" /etc/pki/ca-trust/source/anchors/ldap.crt
  $SUDO update-ca-trust
}

# rename the agent image
function rename() {
    echo "Renaming agent image to moveworks_agent:latest"
    latest_image=$(latest_local_image)
    if [ "$CONTAINER_RUNTIME" == "none" ]; then
        echo "No container runtime found. Please install docker or podman." >&2
        exit 1
    elif [ "$CONTAINER_RUNTIME" == "$docker" ]; then
        $DOCKER image tag "$latest_image" $MOVEWORKS_IMAGE || {
            printErr "Failed to tag Docker image." >&2
            exit 1
        }
    elif [ "$CONTAINER_RUNTIME" == "$podman" ]; then
        $PODMAN image tag "$latest_image" "$MOVEWORKS_IMAGE" || {
            printErr "Failed to tag Podman image." >&2
            exit 1
        }
    fi
}

# helper function to read agent  version
function read_agent_version() {
    echo "Check latest version from  https://gallery.ecr.aws/moveworks/agent"
    read -r -p "Enter agent version[Press return to choose latest]: " AGENT_VERSION
    if [ -z "$AGENT_VERSION" ]; then
        AGENT_VERSION=$LATEST_AGENT_VERSION
         echo "Choosing Default latest version as $LATEST_AGENT_VERSION"
    fi
}

function latest_local_image() {
  # Get all local images for the specified image name
  if [ "$CONTAINER_RUNTIME" == "none" ]; then
      echo "No container runtime found. Please install docker or podman."
      exit 1
  elif [ "$CONTAINER_RUNTIME" == "$docker" ]; then
      images=$($DOCKER images --format "{{.Repository}} {{.Tag}} {{.CreatedAt}}" | grep "moveworks/agent")
  elif [ "$CONTAINER_RUNTIME" == "$podman" ]; then
      images=$($PODMAN images --format '{{.Repository}} {{.Tag}} {{.CreatedAt}}' | grep "moveworks/agent")
  fi

  if [ -z "$images" ]; then
      echo "No local images found for the image name 'moveworks'."
      exit 1
  fi

  # Sort images based on the creation date (most recent first)
  latest_image=$(echo "$images" | sort -r -k 3 | head -n 1)

  # Combine repository and tag in "repository:tag" format
  echo "$latest_image" | awk '{print $1":"$2}' | tr -d '\n'
}

function install_docker() {
  echo "Installing Docker..."
  check_Distribution
  #Docker script doesnt support Amazon Linux
  if [ "$SYSTEM_TYPE" == "amzn" ] ; then
    $SUDO "$YUM" update -y || {
        printErr "Error updating the system. Update the system and Rerun" >&2
        exit 1
    }
    if ! command_exists amazon-linux-extras; then
        $SUDO  install -y amazon-linux-extras
    fi
    amzn_extras=$(command -v amazon-linux-extras)
    $SUDO "$amzn_extras" install -y docker || {
        printErr "Error installing Docker. Install Docker and Rerun" >&2
        exit 1
    }
    #Docker script doesn't support non s390x RHEL arch
  elif [ "$SYSTEM_TYPE" == "rhel" ] && [ "$(uname -m)" != "s390x" ]  ; then
    $SUDO "$YUM" install -y yum-utils || {
        printErr "Error installing yum-utils to install docker. Install docker and Rerun" >&2
        exit 1
    }
    yum_manager=$(command -v yum-config-manager)
    $SUDO "$yum_manager" --add-repo https://download.docker.com/linux/centos/docker-ce.repo || {
        printErr "Error adding Docker repository to package sources. Install Docker and Rerun" >&2
        exit 1
        }
    $SUDO "$YUM" install -y docker-ce docker-ce-cli || {
        printErr "Error installing Docker. Install Docker and Rerun" >&2
        exit 1
    }
  else
    $CURL -fsSL https://get.docker.com -o install-docker.sh || {
        printErr "Error downloading Docker installation script, Install Docker and Rerun" >&2
        exit 1
    }
    $SUDO sh "$AGENT_DIR"/install-docker.sh --version $DOCKER_VERSION_LATEST || {
        printErr "Error installing Docker, Install Docker and Rerun" >&2
        $RM -rf install-docker.sh
        exit 1
    }
    $RM -rf install-docker.sh
  fi
  # Setting the Binary
  DOCKER=$(command -v docker)
}

function install_podman() {
    echo "Installing Podman..."
    check_Distribution
    # shellcheck source=/dev/null
    source /etc/os-release

    if [ "$SYSTEM_TYPE" == "debian" ] ; then
        VERSION_NUMBER=$(echo "$VERSION_ID" | tr -d '"')
        if [ "$VERSION_NUMBER" -ge 11 ]; then
            $SUDO "$APTGET" -y install podman || {
                printErr "Error installing Podman. Install Podman and rerun." >&2
                exit 1
            }
        else
            printErr "Unsupported Version, Install Podman and Retry"
        fi
    elif [ "$SYSTEM_TYPE" == "ubuntu" ] ; then
        # Debian-based system (e.g., Ubuntu)
        VERSION_NUMBER=$(echo "$VERSION_ID" | tr -d '"')
        # Ubuntu version lower than 20.10 doesn't have Podman in the official repository adding repository is required
        if (( $(compare_values "$VERSION_NUMBER" "20.10" le) )); then
            ### download package
            echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_NUMBER}/ /" | $SUDO "$TEE" /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list || {
                printErr "Error adding Podman repository to package sources. Install Podman and Rerun" >&2
                exit 1
            }
            ## add gpg key
            $CURL -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_"${VERSION_NUMBER}"/Release.key | $SUDO apt-key add  || {
                printErr "Error adding GPG key for Podman repository. Install Podman and Rerun" >&2
                exit 1
            }
            $SUDO "$APTGET" -y update ||
            {
                printErr "Error installing Podman Install Podman and Rerun" >&2
                exit 1
            }
            $SUDO "$APTGET" -y  upgrade ||
            {
                printErr "Error installing Podman Install Podman and Rerun" >&2
                exit 1
            }
        else
            # shellcheck disable=SC2086
            $SUDO $APTGET update  ||
            {
                printErr "Error installing Podman. Install Podman and Rerun" >&2
                exit 1
            }
        fi

        $SUDO "$APTGET" -y install podman || {
            printErr "Error installing Podman. Install Podman and Rerun" >&2
            exit 1
        }
    elif [ "$SYSTEM_TYPE" == "rhel" ]; then
        # RHEL
        if (( $(compare_values "$VERSION_ID" "8" "ge") )) && (( $(compare_values "$VERSION_ID" "9" "lt") )); then
            $SUDO "$YUM" module enable -y container-tools:rhel8 || {
                printErr "Error installing Podman. Install Podman and Rerun" >&2
                exit 1
            }
            $SUDO "$YUM" module install -y container-tools:rhel8  || {
                printErr "Error installing Podman. Install Podman and Rerun" >&2
                exit 1
            }
        else
            printErr "Unsupported RHEL version for Podman Installation. Install Podman manually. and rerun" >&2
            exit 1
        fi
    elif [ "$SYSTEM_TYPE" == "centos" ] || [ "$SYSTEM_TYPE" == "amzn" ] ; then
      $SUDO "$YUM" -y install podman || {
          printErr "Error installing Podman. Install Podman and Rerun" >&2
          exit 1
      }
    else
        printErr "Unsupported system type. Install Podman and retry." >&2
        exit 1
    fi
    #setting the podman binary
    PODMAN=$(command -v podman)
}

# Function to check the container runtime and installation
function check_container_installation() {
  #setting up lingering for non-root user
   if [ "$NON_ROOT_USERNAME" != "root" ]; then
        echo "Enabling linger for $NON_ROOT_USERNAME"
        if command_exists loginctl; then
          $LOGINCTL enable-linger "$NON_ROOT_USERNAME" || {
              printErr "Error enabling linger for $NON_ROOT_USERNAME" >&2
          }
        else
          printErr "Loginctl not installed. Error enabling linger for $NON_ROOT_USERNAME" >&2
        fi
   fi
    case $CONTAINER_RUNTIME in
        "$docker")
            docker_version=$(docker_installed_version)
            if [ "$docker_version" != "not installed" ]; then
                echo "Docker version: $docker_version"

                if (( $(compare_values "$docker_version" "$DOCKER_VERSION" "ge") )); then
                    echo "Docker is already installed and meets the minimum required version."
                else
                    printErr "Docker version $docker_version does not meet the minimum required version $DOCKER_VERSION. Uninstall Docker and rerun."
                fi

            else
                install_docker
            fi
             # Configure Docker to start on boot with systemd
            if command -v systemctl &> /dev/null; then
                # System uses systemd
                $SUDO "$SYSTEMCTL" enable docker.service || {
                    printErr "Error enabling Docker service to start on boot" >&2
                }
                $SUDO "$SYSTEMCTL" start docker.service || {
                    printErr "Error starting Docker service" >&2
                }
            else
                echo "Warning: System does not use systemd. Docker service may not start on boot." >&2
            fi
            ;;

        "$podman")
            podman_version=$(podman_installed_version)
            if [ "$podman_version" != "not installed" ]; then
                echo "Podman version: $podman_version"

                if (( $(compare_values "$podman_version" "$PODMAN_VERSION" "ge") )); then
                    echo "Podman is already installed and meets the minimum required version."
                else
                    printErr "Podman version $podman_version does not meet the minimum required version $PODMAN_VERSION. Please upgrade Podman."
                    install_podman
                fi
            else
                install_podman
            fi
            ;;
    esac
}



# starts agent with docker
function start_docker() {
  case "$1" in
    "--fips")
        $DOCKER_START_AGENT_FIPS $MOVEWORKS_IMAGE
        ;;
    "--host-network")
        $DOCKER_START_AGENT_HOST_NETWORK $MOVEWORKS_IMAGE
        ;;
    *)
        $DOCKER_START_AGENT $MOVEWORKS_IMAGE
        ;;
  esac
}

#starts agent with podman and echo the container name
function start_podman() {
  $PODMAN_START_AGENT $MOVEWORKS_IMAGE
  # Fetch the container name with the latest status
  LATEST_CONTAINER_NAME=$($PODMAN ps --latest --format "{{.Names}}")
  echo "$LATEST_CONTAINER_NAME"
}

function start_agent() {
     echo "Starting agent"
     set_common_options
     AGENT_COUNT=$($CONTAINER_RUNTIME ps | grep -c "moveworks_agent")
     if [ "$AGENT_TO_BE_STOPPED" != "0" ]; then
       # AGENT_TO_STOPPED is only set when we are upgrading the agent.
       # In normal case agent to start is already set
         AGENT_TO_START=$AGENT_TO_BE_STOPPED
         AGENT_COUNT=0
     fi
     if [ "$CONTAINER_RUNTIME" == "$podman" ]; then
       # Creating systemd directory if it doesn't exist
         if [ "$NON_ROOT_USER" == "root" ]; then
              if ! [ -d "/etc/systemd/system" ]; then
                  mkdir -p /etc/systemd/system || {
                      printErr "Error creating directory /etc/systemd/system. Create the directory and Rerun" >&2
                      exit 1
                  }
              fi
        else
            if ! [ -d "$HOME/.config/systemd/user" ]; then
                mkdir -p "$HOME"/.config/systemd/user || {
                    printErr "Error creating directory $HOME/.config/systemd/user. Create the directory and Rerun" >&2
                    exit 1
                }
            fi
        fi
         for ((i=AGENT_COUNT+1; i<=AGENT_COUNT+AGENT_TO_START; i++)); do
             LATEST_CONTAINER_NAME=$(start_podman | tail -n 1)
             # If we are upgrading the agent, we don't need to generate the systemd file and rename the container
             # We just need to start the container
             # If we are not upgrading the agent, we need to rename the container, generate the systemd file.
             # And enable the systemd service
             if [ "$IS_UPGRADE" == "false" ]; then
                 $PODMAN rename "$LATEST_CONTAINER_NAME" moveworks_agent_"${i}" >/dev/null 2>&1 || {
                     $PODMAN rename moveworks_agent_"${i}" "temp_$(date +%s)"
                     $PODMAN rename "$LATEST_CONTAINER_NAME" moveworks_agent_"${i}" || {
                       printErr "Error renaming Podman container $LATEST_CONTAINER_NAME to moveworks_agent_${i}" >&2
                       exit 1
                     }
                 }

                 if [ "$NON_ROOT_USER" == "root" ]; then
                      if ! [ -f "/etc/systemd/system/container-moveworks_agent_${i}.service" ]; then
                         $PODMAN generate systemd --new --files --name moveworks_agent_"${i}" || {
                             printErr "Error generating systemd unit file for Podman container moveworks_agent_${i}" >&2
                             exit 1
                         }
                         $SUDO "$MV" -Z container-moveworks_agent_"${i}".service /etc/systemd/system/
                      fi
                 else
                      if ! [ -f "$HOME/.config/systemd/user/container-moveworks_agent_${i}.service" ]; then
                         $PODMAN generate systemd --new --files --name moveworks_agent_"${i}" || {
                             printErr "Error generating systemd unit file for Podman container moveworks_agent_${i}" >&2
                             exit 1
                         }
                         $SUDO "$MV" -Z container-moveworks_agent_"${i}".service "$HOME"/.config/systemd/user/
                      fi
                 fi
             fi
         done
         if [ "$IS_UPGRADE" == "false" ]; then
             if [ "$NON_ROOT_USER" == "root" ]; then
                 $SYSTEMCTL daemon-reload  || {
                    printErr "Error reloading systemd daemon for Podman containers" >&2
                    exit 1
                 }
            else
               $SYSTEMCTL --user daemon-reload  || {
                   printErr "Error reloading systemd daemon for Podman containers" >&2
                   exit 1
               }
            fi

             for ((i=AGENT_COUNT+1; i<=AGENT_COUNT+AGENT_TO_START; i++)); do
               if [ "$NON_ROOT_USER" == "root" ]; then
                  $SYSTEMCTL  enable container-moveworks_agent_"${i}".service || {
                     printErr "Error enabling service for Podman container moveworks_agent_${i}" >&2
                     exit 1
                  }
               else
                  $SYSTEMCTL --user enable container-moveworks_agent_"${i}".service || {
                     printErr "Error enabling service for Podman container moveworks_agent_${i}" >&2
                     exit 1
                  }
               fi
             done
         fi
     else
         for ((i=AGENT_COUNT+1; i<=AGENT_COUNT+AGENT_TO_START; i++)); do
             start_docker "$1" || {
                 echo "Error starting Docker container" >&2
                 exit 1
             }
         done
     fi
 }

 function start() {
  read_agent_version
   # Pull Container Image from Public ECR Repository
  if [ "$CONTAINER_RUNTIME" == "$podman" ]; then
      # Pull image as non-root user
      $PODMAN pull "$ECR_URL$AGENT_VERSION" || {
        printErr "Error: Failed to pull agent image with version '$AGENT_VERSION' using podman from ECR repository '$ECR_URL'."
        exit 1
      }
    else
      $DOCKER pull "$ECR_URL$AGENT_VERSION" || {
        printErr "Error: Failed to pull agent image with version '$AGENT_VERSION' using docker from ECR repository '$ECR_URL'."
        exit 1
      }
    fi
   # Setup Agent folders & permissions
   init
   fix_permissions
   if [ -s "${AGENT_DIR}/conf/agent_config.yml" ]; then
     read -r -p "Configuration file found. Do you want to set a new configuration? [y/n]: " new_config
     case $new_config in
       [Yy]* )
         configure
         ;;
       [Nn]* )
         echo "Proceeding with existing configuration."
         ;;
       esac
   else
     echo "No configuration found."
     configure
   fi
   read -r -p "Do you want to add required Certificates( If the agent is meant to connect to a Directory system using LDAP)? [y,n]: " certs
   case $certs in
    [Yy]* )
       echo "Please add the root certificate to the following directory as a .pem file /moveworks/certs"
       echo "Then run following command to continue"
       echo "sudo ./setup_agent.sh --start"
       exit 1
       ;;
    [Nn]* )
       start_agent
       ;;
    esac
 }

function install(){
  # Agent Installation
  check_container_installation
  read -rp "Enter the number of Agents to Start : " AGENT_TO_START
  start
}

function upgrade(){
  # Upgrade Agent
  #Check if there is any recovery file there which has pending agents to be stopped, if yes then stop them
  IS_UPGRADE=true
  if [ -f "$AGENT_TEMP_FILE" ] && [ "$(cat "$AGENT_TEMP_FILE")" -gt 0 ]; then
        AGENT_TO_BE_STOPPED=$(cat "$AGENT_TEMP_FILE")
  else
    if [ "$CONTAINER_RUNTIME" == "$docker" ]; then
        check_root
        AGENT_TO_BE_STOPPED=$($DOCKER ps | grep -c "moveworks_agent")
      else
        AGENT_TO_BE_STOPPED=$($PODMAN ps | grep -c "moveworks_agent")
    fi
    start
    if [ ! -d "$AGENT_TEMP_DIR" ]; then
      mkdir -p "$AGENT_TEMP_DIR"
    fi
    echo "$AGENT_TO_START">>"$AGENT_TEMP_FILE"
  fi

  stop
  $RM -rf "$AGENT_TEMP_FILE"
}

# stop all running agents
#This function changes the value of AGENT_STOPPED and AGENT_COUNT
function stop() {
    echo "Stopping agents"

    if [ "$CONTAINER_RUNTIME" == "none" ]; then
        echo "No container runtime found. Please install docker or podman." >&2
        exit 1
    elif [ "$CONTAINER_RUNTIME" == "$docker" ]; then
        AGENT_STOPPED=$($DOCKER ps | grep -c "moveworks_agent")
        if [ "$AGENT_TO_BE_STOPPED" -gt 0 ]; then
          # Case when we are upgrading the agent
          # By default, docker ps shows the container in order of creation
          # So we are using tail to get last AGENT_TO_BE_STOPPED containers
            # shellcheck disable=SC2046
            $DOCKER stop $($DOCKER ps -q | tail -n "$AGENT_TO_BE_STOPPED") || {
                printErr "Error stopping Docker containers." >&2
                exit 1
            }
            AGENT_COUNT=$((AGENT_COUNT - AGENT_TO_BE_STOPPED))
        elif [ "$AGENT_STOPPED" -gt 0 ]; then
          # Case when stop all agents

          read -r -p "This will stop all the agents. Do you want to continue [y,n]: " yn
           if [[ "$yn" =~ ^[Nn] ]]; then
               exit 1
           fi
          # shellcheck disable=SC2046
          $DOCKER stop $($DOCKER ps -q) || {
                printErr "Error stopping Docker containers." >&2
                exit 1
            }
          AGENT_COUNT=0
        else
            echo "No Docker containers running."
        fi

    elif [ "$CONTAINER_RUNTIME" == "$podman" ]; then
        AGENT_STOPPED=$($PODMAN ps | grep -c "moveworks_agent")
        if [ "$AGENT_TO_BE_STOPPED" -gt 0 ]; then
          # Case when we are upgrading the agent
            for ((i=1; i<=AGENT_TO_BE_STOPPED; i++)); do
              # disabling and stopping the old systemd service
              if [ "$NON_ROOT_USER" == "root" ]; then
                 $SYSTEMCTL disable --now container-moveworks_agent_"${i}".service  || {
                      printErr "Error disabling or stopping service for Podman container $i." >&2
                      exit 1
                 }
              else
                 $SYSTEMCTL --user disable --now container-moveworks_agent_"${i}".service  || {
                      printErr "Error disabling or stopping service for Podman container $i." >&2
                      exit 1
                 }
              fi
            done
              if [ "$NON_ROOT_USER" == "root" ]; then
                  $SYSTEMCTL daemon-reload  || {
                      printErr "Error reloading systemd daemon for Podman containers." >&2
                      exit 1
                  }
              else
                  $SYSTEMCTL --user daemon-reload  || {
                      printErr "Error reloading systemd daemon for Podman containers." >&2
                      exit 1
                  }
              fi
              # agent which fails to stop(non systemd old agents) with systemctl disable now
              extra_agent_count=$(($($PODMAN ps | grep -c "moveworks_agent")-AGENT_TO_BE_STOPPED))
              if [ "$extra_agent_count" -gt 0 ]; then
                # By default podman ps shows the oldest container first, Using head for same
                # shellcheck disable=SC2046
                $PODMAN stop $($PODMAN ps -q --sort=created | head -n "$extra_agent_count") || {
                    printErr "Error stopping Podman containers." >&2
                    exit 1
                }
              fi
              AGENT_COUNT=$((AGENT_COUNT - AGENT_TO_BE_STOPPED))

              for ((i=1; i<=AGENT_TO_BE_STOPPED; i++)); do
                if [ "$NON_ROOT_USER" == "root" ]; then
                   $SYSTEMCTL  enable  container-moveworks_agent_"${i}".service  || {
                        printErr "Error enabling service for Podman container $i." >&2
                        exit 1
                   }
                else
                   $SYSTEMCTL --user enable  container-moveworks_agent_"${i}".service  || {
                        printErr "Error enabling service for Podman container $i." >&2
                        exit 1
                   }
                fi
              done
              if [ "$NON_ROOT_USER" == "root" ]; then
                  $SYSTEMCTL daemon-reload  || {
                      printErr "Error reloading systemd daemon for Podman containers." >&2
                      exit 1
                  }
              else
                  $SYSTEMCTL --user daemon-reload  || {
                      printErr "Error reloading systemd daemon for Podman containers." >&2
                      exit 1
                  }
              fi
        elif [ "$AGENT_STOPPED" -gt 0 ]; then
          # Case when stop all agents
           read -r -p "This will stop all the agents. Do you want to continue [y,n]: " yn

           if [[ "$yn" =~ ^[Nn] ]]; then
               exit 1
           fi

            $PODMAN rm -fa || {
                printErr "Error removing Podman containers." >&2
                exit 1
            }
            AGENT_COUNT=0
            for ((i=1; i<=AGENT_STOPPED; i++)); do

              if [ "$NON_ROOT_USER" == "root" ]; then
                 $SYSTEMCTL disable --now container-moveworks_agent_"${i}".service  || {
                      printErr "Error disabling or stopping service for Podman container $i." >&2
                      exit 1
                 }
              else
                 $SYSTEMCTL --user disable --now container-moveworks_agent_"${i}".service  || {
                      printErr "Error disabling or stopping service for Podman container $i." >&2
                      exit 1
                 }
              fi
            done

            if [ "$NON_ROOT_USER" == "root" ]; then
                $SYSTEMCTL daemon-reload  || {
                    printErr "Error reloading systemd daemon for Podman containers." >&2
                    exit 1
                }
            else
                $SYSTEMCTL --user daemon-reload  || {
                    printErr "Error reloading systemd daemon for Podman containers." >&2
                    exit 1
                }
            fi
        else
            echo "No Podman containers running."
        fi
    fi
}

# Check if an argument is provided
if [ -z "$1" ]; then
    echo "Missing argument."
    show_usage
    exit 1
fi

# Main script
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
         --docker)
              CONTAINER_RUNTIME="$docker"
              check_root
              echo "Container Runtime selected: $CONTAINER_RUNTIME"
              install "$2"
              exit 0
              ;;
         --podman)
            CONTAINER_RUNTIME="$podman"
            echo "Container Runtime selected: $CONTAINER_RUNTIME"
            install
            exit 0
            ;;
         -u|--upgrade)
            upgrade "$2"
            exit 0
            ;;
        -i|--init)
            check_root
            init
            exit 0
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        -c|--configure)
            configure
            exit 0
            ;;
        -s|--start)
            start_agent "$2"
            exit 0
            ;;
        -t|--stop)
            stop
            exit 0
            ;;
        -v|--validate)
            validate
            exit 0
            ;;
        -p|--permissions)
            check_root
            fix_permissions
            exit 0
            ;;
        -f|--fetch)
            fetch_ldap_certificate
            exit 0
            ;;
        -d|--debug)
            LOG_LEVEL="${DEBUG_LEVEL}"
            start_agent "$2"
            exit 0
            ;;
        *)
            echo "Invalid option: $key"
            show_usage
            exit 1
            ;;
    esac
done
