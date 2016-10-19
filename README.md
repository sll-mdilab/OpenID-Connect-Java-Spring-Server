# Identity Provider

## Introduction
This is a fork of [MITREid Connect] (https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server) with some minor modifications. The most significant change is the addition of support for SITHS X509 certificates.

User authentication and client details are stored in an in-memory database of which the content is taken from SQL-files under `openid-connect-server-webapp/src/main/resources/db/`.

