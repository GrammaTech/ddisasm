FROM ubuntu:18.04

RUN apt-get -y update && \
    apt-get -y install python2.7 clang-format git curl

RUN curl https://llvm.org/svn/llvm-project/cfe/trunk/tools/clang-format/git-clang-format > /usr/bin/git-clang-format
RUN chmod +x /usr/bin/git-clang-format

COPY . /gt/ddisasm/
WORKDIR /gt/ddisasm/

## Run clang-format on the last commit
RUN git clang-format origin/master --extensions cpp,h

## Run clang-format on all source files.
# RUN (find src -name "*.cpp" -or -name "*.h")|xargs -I{} clang-format -i {}
# RUN [[ $(git diff --shortstat 2> /dev/null | tail -n1) == "" ]]
