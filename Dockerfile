# Build Container
FROM golang:1.13.4-alpine3.10 AS build-env
MAINTAINER Ice3man (nizamul@projectdiscovery.io)
RUN apk add --no-cache --upgrade git openssh-client ca-certificates
RUN go get -u github.com/golang/dep/cmd/dep
WORKDIR /go/src/app

# Install
RUN go get -u github.com/projectdiscovery/subfinder/v2/cmd/subfinder

ENTRYPOINT ["subfinder"]
