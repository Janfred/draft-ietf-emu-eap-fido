---
title: "EAP-FIDO"
abbrev: "EAP-FIDO"
category: info

docname: draft-janfred-eap-fido-latest
submissiontype: independent
v: 3
keyword:
 - EAP
 - FIDO

author:
  - name: Jan-Frederik Rieckers
    org: Deutsches Forschungsnetz | German National Research and Education Network
    street: Alexanderplatz 1
    code: 10178
    city: Berlin
    country: Germany
    email: rieckers@dfn.de
    abbrev: DFN
    uri: www.dfn.de
  - name: Stefan Winter
    org: Fondation Restena | Restena Foundation
    street: 2, avenue de l'Université
    code: 4365
    city: Esch-sur-Alzette
    country: Luxembourg
    email: stefan.winter@restena.lu
    abbrev: RESTENA
    uri: www.restena.lu


normative:

informative:
  WebAuthn:
    title: "Web Authentication: An API for accessing Public Key Credentials Level 2"
    author:
      org: World Wide Web Consortium
    date: 2021-04-08
    target: https://www.w3.org/TR/2021/REC-webauthn-2-20210408/
  FIDO-CTAP2:
    title: Client to Authenticator Protocol (CTAP)
    author:
      org: FIDO Alliance
    date: 2022-06-21
    target: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html
  FIDO-SecRef:
    title: FIDO Security Reference
    author:
      org: FIDO Alliance
    date: 2022-05-23
    target: https://fidoalliance.org/specs/common-specs/fido-security-ref-v2.1-ps-20220523.html
  FIDO-Glossary:
    title: FIDO Technical Glossary
    author:
      org: FIDO Alliance
    date: 2022-05-23
    target: https://fidoalliance.org/specs/common-specs/fido-glossary-v2.1-ps-20220523.html


--- abstract

This document specifies an EAP method leveraging FIDO2 keys for authentication in EAP.

--- middle

# Introduction

The Extensible Authentication Protocol (EAP) {{?RFC3748}} is a widely used standard that allows a server to authenticate a client using different authentication methods.
There is a huge variety of EAP methods available, that serve different purposes and have different security implications.

Two common EAP methods are EAP-PEAP and EAP-TTLS {{?RFC5281}}, that both use EAP-TLS {{!RFC5216}} to provide confidentiality of the inner authentication.
This inner authentication is most commonly password-based, meaning that an attacker that manages to compromise the TLS connection can eavesdrop on the authentication and observe the password.
The authentication of the server to the client within the TLS handshake thus is a vital security function of these EAP methods.

The operational praxis has shown that this is a common problem and security flaw.
The specification for EAP-TLS {{RFC5216}} does not include guidance on how to decide if a certificate is valid for this specific authentication.
This standardization gap has lead to user interfaces, where the default setting for certificate validation was set to "Do not validate".
Even if the validation is active, the supplicant has no implicit information to determine the expected subject name in the server's certificate, so users need to manually configure the expected domain.
Failure to configure this or not configuring it at all could again lead to an attacker being able to compromise the TLS connection and, as a result, also the password sent in the inner authentication.

There are two major security problems here, that this specification wants to address.
Firstly, the use of passwords as authentication method implies that the password needs to be sent to the server.
If an attacker observes this exchange, they can impersonate the user at any time.
Therefore, this specification uses FIDO authentication, which is based on asymmetric cryptography.
With this method, even if an attacker is able to compromise the TLS connection, they cannot impersonate the user based on the observed data.

The second major security problem is the specification gap regarding certificate validation.
With EAP-FIDO, the supplicants now have a clear specification on how to decide wether or not a server certificate is considered valid for the current authentication flow.
This is achieved by using the trust anchors available on most devices and a method to determine the valid server name based on implicit information of the authentication configuration.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Overview over the EAP-FIDO protocol

The EAP-FIDO protocol comprises two phases: the TLS handshake phase and FIDO-exchange phase.

During the TLS handshake phase, TLS is used to authenticate the EAP-FIDO server to the client.

During the FIDO-exchange phase, the actual FIDO authentication is executed and the client authenticates itself to the server.

Once the FIDO exchange is completed successfully, the client and server can derive keying material from the TLS handshake phase implicitly.


## TLS handshake phase

During the TLS handshake phase, the client and server establish a TLS tunnel.
This is done using EAP-TLS {{RFC5216}}, {{!RFC9190}} with the modifications described in TODO:SECTION LINK.
As part of the TLS handshake protocol, the EAP-FIDO server will send its certificate along with a chain of certificates leading to the certificate of a trusted CA.
The client will check this certificate using the rules in TODO:SECTION LINK.

Once the TLS tunnel is established, the client and server proceed to the FIDO-exchange phase to perform the authentication of the client.

## FIDO-exchange phase

In this phase, the TLS record layer is used to securily tunnel information between the EAP-FIDO client and EAP-FIDO server.

For the FIDO-exchange phase, the client has two options, depending on the configuration and the capability of the FIDO token.

If the FIDO token supports residential keys and EAP-FIDO is configured to use these for authentication, the client generates a challenge from the TLS keying material and triggers a FIDO challenge.

If the client is not configured to use residential keys, the client first needs to send its username to the server.
The server will answer with a list of FIDO key IDs and the client will attempt to use one of these keys to authenticate.

# EAP-FIDO protocol flow




# Implementation Guidelines

# Design decisions

This section documents several design decisions for the EAP-FIDO protocol

## Registration of FIDO2 keys is out of scope

The FIDO CTAP2 protocol has distinct primitives for the registration and the usage of a FIDO2 credential. This specification requires that the registratrion of the security token has been done out-of-band, for example using the WebAuthN protocol in a browser context.

There are multiple degrees of freedom when registering a token with CTAP2. This specification recognises the following choices at registration time, and defines how to effectuate an authentication transaction for any combination of these choices.

### Discoverable credentials vs. Non-Discoverable credentials

FIDO2 tokens contain a master key which never leaves the security perimeter of the token exists on the device. FIDO2 tokens transact by generating asymetric keypairs which are bound to a scope (often: a domain name, a RADIUS realm). The scoped keying material is saved in either of two locations:

- Non-Discoverable Credentials: All the keying material is stored on the server-side. The private key is encrypted with the token-specific master key so that the server can store, but not use, the device's private key. During authentication transactions, the keying material is sent to the token for local decryption and usage. The security token itself does not store any data persistently; it is stateless and thus the number of keypairs and scopes it manages is infinite.

- Discoverable Credentials: The keying material is stored on the security token itself, along with the scope for which the keypair was generated. During authentication transactions, only the scope (as configured, or as sent by the server) determines which keypair is to be used in the transaction. The key can store multiple keys for the same scope. The number of keypairs that can be stored on the key is finite.

EAP-FIDO supports both Discoverable and Non-Discoverable credentials.

### User involvement during registration

Token registration can involve one of two levels of asserting the user presence:

- UP (userPresence): the registration ceremony ensures that a person is present at the token while registering the device (e.g. human tissue needs to touch a physical security key while the registration transaction executes).
- UV (userVerification): the security token registers a unique property of the user during the registration ceremony, such that it is asserted that only the exact same person can interact with the token in the future (e.g. by registering a fingerprint or facial recognition)

Note: during authentication transactions, an EAP-FIDO server can request one of three levels of asserting user presence: 
- Silent (interaction with a human is not required)
- UP (physical interaction with a person is required)
- UV (physical interaction with the registered user is required). 

An authentication transaction can not request a higher level than was set at registration time; i.e. a token registered in UP mode can not transact in UV mode.

EAP-FIDO supports all three transaction modes, and the server can signal its required minimum assertion level for each individual authentication transaction.

## FIDO2 key scopes

The scope of a FIDO2 key as set during the registration transaction determines the contexts in which it can be used. In EAP-FIDO, the following three notions interplay:

- the realm of username as used in the EAP-Identity exchange ("outer ID")
- the servername as presented during the EAP-TLS exchange by the EAP-FIDO server
- the relyingPartyIdentifier (rpId) that is used during the FIDO CTAP2 client authentication phase

EAP-FIDO requires the registered scope to be:

- identical to the realm in the outer ID
- within the same second-level domain as the EAP-TLS server certificate will be
- within the same second-level domain as the FIDO rpId

## EAP-Method with EAP-TLS vs standalone EAP method to be used in tunnels

Since there already exist EAP methods that provide a TLS tunnel and are capable of encapsulating further EAP methods, e.g. EAP-PEAP or EAP-TTLS, the question arises, why this specification does not focus solely on the FIDO exchange as a standalone EAP method instead of re-specifying a new EAP-method that again makes use of EAP-TLS.

The main reason for a decision against this is the potential for misconfiguration.
One of the goals for this EAP method is to provide a means to validate the server certificate using implicit configuration options.
Using EAP-TTLS or EAP-PEAP would counteract this goal, since in most supplicants the configuration for the different phases of the tunneled TLS methods is done seperately, so the users would have to configure the certificate check parameters manually again.
Additionally, not every supplicant application allows access to information about the phase 1 exchange, namely the server certificate parameters, which is neccessary for the security of the EAP-FIDO exchange.
Specifying EAP-FIDO as standalone EAP methods would therefore require modifying the EAP-TTLS or EAP-PEAP stack.
Implementers might be tempted to re-use the insecure and error-prone configuration interfaces.
To prevent this from the start, EAP-FIDO specifies an EAP-TLS based EAP method that cannot be used standalone.

Although this requires protentially duplicate code for supplicants that support multiple EAP-TLS based methods, the authors believe this means of specification to be more resistant against implementation errors and prevent error-prone user interfaces.



# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
