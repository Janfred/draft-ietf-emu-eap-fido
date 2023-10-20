---
title: "EAP-FIDO"
abbrev: "EAP-FIDO"
category: std

docname: draft-janfred-eap-fido-latest
submissiontype: IETF
v: 3
area: "Security"
workgroup: "EAP Method Update"
keyword:
 - EAP
 - FIDO
 - TLS
venue:
  group: "EAP Method Update"
  type: "Working Group"
  mail: "emu@ietf.org"

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

{:jf: source="Janfred"}

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
This is done using EAP-TLS {{RFC5216}}, {{!RFC9190}}, {{!RFC9427}} with the modifications described in TODO:SECTION LINK.
As part of the TLS handshake protocol, the EAP-FIDO server will send its certificate along with a chain of certificates leading to the certificate of a trusted CA.
The client will check this certificate using the rules in TODO:SECTION LINK.

Once the TLS tunnel is established, the client and server proceed to the FIDO-exchange phase to perform the authentication of the client.

## FIDO-exchange phase

In this phase, the TLS record layer is used to securily tunnel information between the EAP-FIDO client and EAP-FIDO server.

For the FIDO-exchange phase, the client has two options, depending on the configuration and the capability of the FIDO token.

If the FIDO token supports residential keys and EAP-FIDO is configured to use these for authentication, the client generates a challenge from the TLS keying material and triggers a FIDO challenge.

If the client is not configured to use residential keys, the client first needs to send its username to the server.
The server will answer with a list of FIDO key IDs and the client will attempt to use one of these keys to authenticate.

# EAP-FIDO protocol flow and message format

This section describes the preconditions and the configuration needed for EAP-FIDO, the protocol flow and the message format

## Preconditions and Configuration

In order to successfully perform an EAP-FIDO authentication, the server and the client have to meet some preconditions and need to have a configuration.

EAP-FIDO assumes that the FIOD authenticator is already registered with the server, that is, the EAP-FIDO server has access to the public key used to verify the authenticator's response as well as the corresponding credential id.

On the client side, the supplicant must be configured with the Relying Party ID (see {{openquestions_rpid}}, and, if Passkeys are not used, with a Username.

## TLS handshake phase

The packet format for EAP-FIDO messages follows the format specified in {{RFC5216, Section 3}} with the following modifications:

* The Type field is set to TODO [awaiting IANA early allocation] (EAP-FIDO)
* Within the Flags field, the Version bits are set to the major version of EAP-FIDO. For this specification, the version is 0. Future EAP-FIDO versions MAY increase the version number.

### EAP-FIDO Start packet

In the first packet from the server to the client, the S-bit of the Flags MUST be set, indicating the start of the EAP-FIDO protocol.
It MUST NOT be set in any subsequent packet.

[^RPID_Option1]{:jf}

[^RPID_Option1]: Depending on the decision on the way, the RPID is determined, some additional spec may be added here, see {{openquestions_rpid}}.

### Version negotiation

The version of EAP-FIDO is negotiated in the first exchange between server and client.
The server sets the highest major version number of EAP-FIDO that it supports in the V field of the flags in its Start message.
In the case of this specification, this is 0.
In its first EAP message in response, the client sets the V field to the highest major version number that it supports that is no higher than the version number offered by the server.
If the client version is not acceptable to the server, it sends an EAP-Failure to terminate the EAP session.
Otherwise, the version set by the client is the version of EAP-FIDO that MUST be used and both server and client MUST set the V field to that version number in all subsequent EAP messages.

Given the limited range of the V field (values 0-7), future EAP-FIDO versions MUST NOT increase the major version if there are no changes to the outer message format.
Minor version updates that only affect the inner protocol flow MUST be done with means available during the TLS handshake, i.e. using Application Layer Protocol Negotiation (ALPN).

### Fragmentation

Each EAP-FIDO message contains a single leg of a half-duplex conversation.
Since EAP carrier protocols may constrain the length of an EAP message, it may be neccessary to fragment an EAP-FIDO message across multiple EAP messages.

The fragmentation method is described in {{RFC5216, Section 2.1.5}}.

### TLS Handshake Requirements

The client and server perform a TLS handshake following the specification in {{RFC5216, Section 2}} and {{RFC9190, Section 2}} with the following modifications:

* TLS version 1.3 or higher MUST be negotiated.
* Mutual authentication is not required. Implementations MUST support EAP-FIDO without TLS client authentication, but MAY allow it, i.e. if EAP-FIDO is used as a 2-Factor authentication method where TLS client certificates are the first factor and the FIDO authentication is the second.
* The certificate of the server MUST be validated. The different options for validation are listed in {{tls_server_cert_verify}}.
* (FIXME, depending on RPID option) The client MUST send the desired Relying Party ID for the FIDO exchange in the Server Name Indication extension.

### TLS Server Certificate Verification
{: #tls_server_cert_verify}

(FIXME: Currently only bulletpoints, will be converted into text)

* Clients MUST support validating against a built-in list of Root CAs, ideally WebPKI.
* Implementations MAY support pinning a trust anchor
* The RPID MUST be validated against the certificate name (How exactly is still TODO)
* TODO: OCSP Stapling? Mandatory or not?

## FIDO-exchange

After the TLS handshake is completed, the client and server perform the FIDO-exchange to authenticate the client inside the TLS tunnel.

This section describes the message format and the protocol flow.


### Message format

All EAP-FIDO messages in the inner authentication consist of a CBOR sequence with two elements:

type:
: integer to indicate the message type. {{msgtypes}} contains a list of the different message types.

attributes:
: a CBOR encoded map with attributes. A list of the different attributes, their assigned mapkey and the type are listed in {{mapkeys}}.

| Type | Description | Sent by |
|------|-------------|-----------|
| -2   | Error | Both |
| -1   | Failure indicator | Both |
| 0    | Success indicator | Both |
| 1    | Authentication Request | Server |
| 2    | Authentication Response | Client |
| 3    | Information Request | Client |
| 4    | Information Response | Server |
{: #msgtypes title="Message types"}

| Mapkey | Type | Label | Description |
|--------|------|-------|-------------|
| 0 | UTF-8 String | Identity | User Identity (usually username) |
| 1 | UTF-8 String | Relying Party ID | See {{openquestions_rpid}} |
| 2 | Byte String | Additional Client Data | Additional Data to be signed by the FIDO authenticator |
| 3 | Array of Byte Strings | PKIDs | List of acceptable Public Key Identifiers |
| 4 | Byte String | Auth Data | Authdata according to {{WebAuthn}}, Section 6.1 |
| 5 | Byte String | FIDO Signature | |
| 6 | Array of UTF-8 Strings | Authentication requirements | Sent by the server to indicate the current authentication requiremens, i.e. if user presence or user verification is required |
| 7 | Byte String | PKID | Needed to identify the credential |
| 8 | Integer | Error Code | A code describing the error |
| 9 | UTF-8 String | Error Description | An optional human-readable error description |
{: #mapkeys title="Mapkeys for the attributes"}

#### Success indicator

This message is the protected success indicator, as required by {{RFC9427, Section 5.2}}.
It is sent by the server to indicate a successfull authentication.
Since EAP is a strict request-response based protocol, the client needs to reply to this message, so the server can send an EAP-Success message.
The client will acknowledge the reception of this packet through the acknowledgement mechanism in EAP-TLS with an EAP-TLS acknowledgement packet.

To achieve the compatibility with the protected success indication mechanism of other EAP methods, the attributes field of the message MUST be omitted, that is, this message is only one byte with the value of 0x00.

#### Failure indicator

A failure indicator message signals a non-recoverable error condition for the current authentication exchange.

The attributes field of the message MUST contain at least the Error Code attribute and MAY contain the Error Description field.

#### Authentication Request

An authentication request is sent by the server to initialize a new authentication request.
With this request, the server sends along information that the client needs to perform the FIDO authentication.

The attributes field in the authentication request message contain the following attributes:

Relying Party ID:
: The Relying Party ID for the FIDO authentication. See {{openquestions_rpid}}.

Additional Client Data:
: (Optional) Additional data to be signed by the FIDO authenticator.

PKIDs:
: (Optional) A list of acceptable Public Key Identifiers. This can be used to trigger a re-authentication of a specific credential or a list of the identifiers for a specific user, if Passkeys are not used.

Authentication Requirements:
: (Optional) A list of requirements for the FIDO authentication. The possible options for this version of EAP-FIDO are "up" for requesting user presence and "uv" for requesting user verification. Clients MUST ignore any other value, to ensure forward compatibility.


Since this packet signals the start of a new authentication, the client MUST discard any information from previous authentication requests and initialize a new authentication, even if the previous authentication exchange was not completed.

#### Authentication Response

If a client has sufficient information to perform a FIDO authentication, the client sends an authentication response. The authentication response signifies the completion of one authentication.
This message can be sent in response to either an Authentication Request or an Information Response.

The attributes field in the authentication response message contain the following attributes:
PKID:
: The Public Key Identifier of the FIDO key used to generate the signature.

Auth Data:
: The signed auth data as returned from the FIDO authenticator (see {{FIDO-CTAP2}}, Section 6.2)

FIDO Signature:
: The signature as returned from the FIDO authenticator (see {{FIDO-CTAP2}}, Section 6.2)


All three attributes MUST be present in the authentication response message.

#### Information Request

If a client does not have sufficient information to perform the FIDO authentication, the client can send an information request message to the server.

This is the case if Passkeys are not used, since the FIDO authenticator needs the public key identifier to access the credentials.

With the information request the client can transmit additional information that help the server to compile this information.

The attributes field in the information request contains the following attributes:

Identity:
: The identity of the user (usually a username)

#### Information Response

The server answers to an Information Request from the client with an Information Response.

This packet is used to transmit additional information to the client.

The attributes field in the information response can contain any attribute that is also allowed in the Authentication Request packet.
If an attribute was both present in the Authentication Request and the Information Response packet, the client MUST discard the attribute value(s) sent in the Authentication Request and use the value(s) in the Information Response packet.

#### Error

The Error message signals an error condition on the client side.
This error condition does not neccessarily lead to an authentication failure, since the EAP-FIDO server may decide that the previous authentication is sufficient. (See {{examples_2hgracetime}} for an example for this use case)

The attributes field MUST include the attribute Error Code with an error code describing the error and MAY contain an Error Description attribute with a human-readable error description.

### Potocol Sequence

The FIDO exchange start with the server sending an authentication request to the client.
This message is sent along with the last message of the server's TLS handshake.

The Authentication Request can include authentication requirements, additional client data and a list of Public Key Identifiers.

The client then decides if it has sufficient information to perform the FIDO authentication.
This can be done by probing the FIDO authenticator with all information given in the Authentication Request message.

If the FIDO authentication is already possible at this point, the client performs the FIDO authentication process and sends an Authentication Response message with the results from the FIDO authentication to the server.
This authentication flow can be used if the FIDO authenticator has a Passkey registered for the given Relying Party ID.

If the client needs additional information, i.e. because it does not use Passkeys and therefore needs a list of Key Identifiers, the client sends an information request to the server, which may include additional information from client to help the server to fulfil the information request.
In the current specification, this is namely an identifier, from which the EAP-FIDO server can perform a lookup for all registered FIDO credentials registered to this identifier.

Upon reception of the Information Request message from the client, the server looks up the registered Public Key Identifiers for the given identity.
Depending on the lookup, the requirements for user presence or user verification may change from the previous assumption.
The found Public Key Identifiers, and optionally also the updated authentication requirements, are then sent with the Information Response back to the client.

The client can now, with the additonal information in the Information Response message, perform the FIDO authentication.
The result of the FIDO authentication is then sent to the Server in an Authentication Response message, which includes the PKID, Auth Data and FIDO Signature from the FIDO authentication result.

When a server receives an Authentication Response message, it validates the FIDO data.
If the FIDO authentication is successful and the FIDO key has sufficient authorization, the server sends a Success indication message to indicate the Success of the FIDO exchange phase.
The client will acknowledge this packet using the EAP-TLS acknowledgement mechanism and the server sends an EAP-Success message.

Depending on the result of the FIDO authentication, the user presence or user verification assertions and the policy for a specific FIDO credential, the server MAY choose to trigger a second FIDO authentication with a different set of authentication requirements.
This is done by sending a new Authentication Request message to the client.
This message MUST include a PKIDs attribute with only the PKID of the credential used in the previous FIDO authentication process.

The client then triggers a new FIDO authentication process and answers with an Authentication Response message.

The server MUST NOT trigger a challenge with the same Public Key Identifier and Authentication Requirements twice.

## FIDO authentication

This section will describe the actual FIDO authentication process, that is performed between the EAP-FIDO client and the FIDO authenticator.

The client will use CTAP version 2.0 or above {{FIDO-CTAP2}} to communicate with the authenticator.

The Relying Party ID  (RPID) either explicitly configured, derived from the RADIUS routing realm, from the server certificate subjectAltName:DNS or sent by the server.
In analogy to WebAuthn, the client needs to verify that the RPID either matches exactly the subjectAltName:DNS of the certificate or that the subjectAltName is a subdomain of the RPID.
For discussion on the topic regarding the relationship RPID, SAN and RADIUS Realm, see {{openquestions_rpid}}.

The client data is a concatenation of two items.

The first item is derived from the TLS keying material:

    FIDO_CHALLENGE_TLS = TLS-Exporter("fido challenge", NULL, 32)

The second item is the optional additional client data sent by the server.

Both items are concatenated and hashed using SHA-256.
The result is the clientDataHash for the FIDO authentication.

# Implementation Guidelines

TODO

# Design decisions

This section documents several design decisions for the EAP-FIDO protocol

## Registration of FIDO2 keys is out of scope

The FIDO CTAP protocol has distinct primitives for the registration and the usage of a FIDO2 credential.
This specification requires that the registratrion of the security token has been done out-of-band, for example using the WebAuthn protocol in a browser context.

There are multiple degrees of freedom when registering a token with CTAP version 2.
This specification recognises the following choices at registration time, and defines how to effectuate an authentication transaction for any combination of these choices.

### Discoverable credentials vs. Non-Discoverable credentials

FIDO2 tokens contain a master key which never leaves the security perimeter of the token exists on the device.
FIDO2 tokens transact by generating asymetric keypairs which are bound to a scope (often: a domain name, a RADIUS realm).
The scoped keying material is saved in either of two locations:

- Non-Discoverable Credentials: All the keying material is stored on the server-side. The private key is encrypted with the token-specific master key so that the server can store, but not use, the device's private key. During authentication transactions, the keying material is sent to the token for local decryption and usage. The security token itself does not store any data persistently; it is stateless and thus the number of keypairs and scopes it manages is infinite.

- Discoverable Credentials: The keying material is stored on the security token itself, along with the scope for which the keypair was generated. During authentication transactions, only the scope (as configured, or as sent by the server) determines which keypair is to be used in the transaction. The key can store multiple keys for the same scope. The number of keypairs that can be stored on the key is finite.

EAP-FIDO supports both Discoverable and Non-Discoverable credentials.

### User involvement during registration

Token registration can involve one of two levels of asserting the user presence.

- UP (userPresence): the registration ceremony ensures that a person is present at the token while registering the device (e.g. human tissue needs to touch a physical security key while the registration transaction executes).
- UV (userVerification): the security token registers a unique property of the user during the registration ceremony, such that it is asserted that only the exact same person can interact with the token in the future (e.g. by registering a fingerprint or facial recognition)

During authentication transactions, an EAP-FIDO server can request one of three levels of asserting user presence.

- Silent (interaction with a human is not required)
- UP (physical interaction with a person is required)
- UV (physical interaction with the registered user is required).

An authentication transaction can not request a higher level than was set at registration time; i.e. a token registered in UP mode can not transact in UV mode.

EAP-FIDO supports all three transaction modes, and the server can signal its required minimum assertion level for each individual authentication transaction.

## FIDO2 key scopes

The scope of a FIDO2 key as set during the registration transaction determines the contexts in which it can be used.
In EAP-FIDO, the following three notions interplay:

- the realm of username as used in the EAP-Identity exchange ("outer ID")
- the servername as presented during the EAP-TLS exchange by the EAP-FIDO server
- the relyingPartyIdentifier (rpId) that is used during the FIDO CTAP client authentication phase

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

# Implementation Status

Note to RFC editor: Remove this section, as well as the reference to {{RFC7942}} before publication

{::boilerplate RFC7942}

There is one early prototype proof-of-concept implementation of EAP-FIDO into hostap (hostapd for the server side, wpa_supplicant on the client side) available.
The implementation was done before the specification of this draft was finished and is therefore not compatible with any draft version (different message format, simplified message flow, missing security checks), but serves as a proof-of-concept for the overall principle of using FIDO to perform an eduroam login.
The source code can be found under [https://git.rieckers.it/rieckers/hostap/-/tree/eap_fido_poc_tnc23](https://git.rieckers.it/rieckers/hostap/-/tree/eap_fido_poc_tnc23)

# Security Considerations

TODO Security


# IANA Considerations

This document has IANA actions:

* EAP type code point for EAP-FIDO
* EAP-FIDO registry
    * Message types
    * Attributes


--- back

# Example use cases and protocol flows

## Authentication using Passkeys with silent authentication
{: #usecases_passkey_silent}

With this use case, the server will send an Authentication Request containing only the Relying Party Id attribute.

The client can trigger the silent authentication with the Passkey stored on the FIDO authenticator and includes the response from the FIDO authenticator into the Authentication Response message.

The server can look up the Public Key Identifier in its database, verify the FIDO signature with the stored public key and, if the signature was valid, send a protected success indicator to the client.
The client responds with an acknowledgement and the server sends an EAP-Success

## Authentication using Passkeys with silent auth for WiFi and uv auth for VPN

With this use case, the server will modify the Authentication Request based on which RADIUS client (the Wifi Controller or the VPN appliance) sent the request.

If the WiFi appliance sent the request, silent auth is used, and the flow is identical with the previous use case.

If the request came from the VPN appliance (e.g. because the VPN is done via IPSEC with EAP), the server adds "uv" in the Authentication Requirements attribute, which triggers an UV action on the client's side.

The client triggers the Passkey authentication with user verification and responds to the server with the authentication data. The server verifies the signature, sends a success indication, the client acknowledges and the server sends an EAP-Success.

## Authentication with non-residential FIDO keys

In this use case, the FIDO authenticator does not have a Passkey for the Relying Party ID. Instead, the server has a list of Public Key Identifiers stored for each username.

After the initial Authentication Request from the server, the client does not have enough data to trigger the FIDO authentication, so it needs additional information.

The client then sends an Information Request message with its username.

The server looks up the username in its database and sends back a list of Public Key Identifiers it has stored for this user with an Information Response message.

The client can now trigger the FIDO authentication with this list and responds with an Authentication Response, that includes the Public Key Identifier that was actually used for this FIDO authentication.

The server can now verify the signature and client and server finalize the EAP method.

## Authentication with non-residential FIDO keys and user-specific authentication policies

In this use case, different users have different authentication policies, i.e. employees are allowed to use silent authentication, but administrators need an authentication with user presence.

The server starts with an AuthenticationRequest and no authentication requirements or an empty array as authentication requirements.
The client transmits its identity to the server in the Information Request message.
Now the server looks up the user and their registered public key identifiers, and checks whether or not user presence verification is necessary.

If it is necessary, the server includes an authentication requirements attribute with the "up" value along with the PKIDs in the Information Response message.
Since the client discards any previous attribute values, it now performs a FIDO authentication with user presence, and responds to the server.

## Authentication with mandatory verification after a timespan

It may be desired to force a user verification after a timespan, to ensure that the FIDO token is still in possession of the user.
This timespan is specific for each token, so the check whether or not the token is still allowed to perform only silent authentication can only be done after the authentication has happened.

Given, a user has two registered token, one was verified recently and the other exceeded the verification timespan.

The server start with an authentication request, the client answers with an Information Request and the Identity, the server transmits the Information Response with the two PKIDs and the client performs the silent FIDO authentication with the "expired" FIDO token.
After sending the Authentication Response, the server verifies the FIDO authentication and recognizes the expired FIDO token.
Now the server sends a new Authentication Request with the PKID of the expired token and "uv" as Authentication Requirement.
The client now performs the FIDO authentication again, this time with user verification and sends the Authentication Response to the server.
The server stores the timestamp of the successful user verification in its database and sends the success indicator.

## Authentication with mandatory verification after a timespan with a grace period
{: #examples_2hgracetime}

As with the previous example, in this case the FIDO token again have a token-specific timeout to allow silent authentication for a period of time after a successful user verification.
Unlike in the previous example, this time there is a grace period that still allows a silent authentication for a while after the timer expired.
The intention is to not kick out the user in the moment the timer expires, i.e. a user is currently not in the vicinity of the device at that time.

The protocol flow is the same as the previous example, but this time the second Authentication Request from the server cannot be answered from the client, since the user is not performing the user verification.
Instead, the client will send an Error message with error code TODO (FIDO authentication Timeout).

The server can now decide whether or not the silent authentication is still acceptable. If it is, it answers with a Success Indicator. If not, the server will send a Failure Indicator with the appropriate error code.

## 2FA-AUthentication with client certificate on TLS layer and FIDO in the inner authentication

Since EAP-FIDO uses TLS, it is possible to perform two-factor authentication directly with only EAP-FIDO.
In this case, the client and server perform mutual authentication at the TLS layer.

The server can now determine the identity of the user based on the certificate and already look up the stored Public Key Identifiers.
With this lookup, the server can already include the PKIDs in the Authentication Request.
The client doesn't need to send an Information Request, since it already has all information.
It can immediately perform the FIDO authentication process and send the Authentication Response to the server.

# Open Questions regarding Protocol design

Note to RFC Editor: Remove this section before publication.

Since this specification is an early draft, there are a lot of open questions that we want to get community feedback on.

## How to determine the FIDO Relying Party ID?
{: #openquestions_rpid}

FIDO needs a relying party ID to function.
The question is how this RPID is determined and verified, there are several options that all have pros and cons.

The main thing is to have in mind, that there are three relevant parameters, that need to be put into a certain relationship:

* the RADIUS realm (i.e. 'anonymous@dfn.de')
* the RPID (i.e. 'eduroam.dfn.de')
* the Server Certificate Name (usually subjectAltName:DNS, i.e. 'radius.eduroam.dfn.de', in the following abbreviated simply with SAN)

All these three parameters need to be in a pre-defined relationship to allow a simple and hard-to-mess-up-and-still-secure configuration.
Both the client and the server have to agree on what the RPID is, in order for the FIDO authentication to succeed.
If there is a defined relationship between the RPID and the certificate name (i.e. SAN needs to be a subrealm of the RPID), then the client needs to verify the certificate against exactly that.
When does the client do that? What security implications does that bring?
All these options need some thought.

### Option 1: Configuration
The first option would be to just have the RPID as a configuration item, maybe with a default on the realm of the outer username.
Adding a configuration option complicates the setup of the EAP method, but hopefully not too much.
A misconfiguration of the RPID is also not that critical from a security standpoint.
The effects of a misconfigured RPID are only a problem if the used FIDO key is also registered with a third party, in which case the third party could trick the client to connect to a bogous network.

If the RPID deviates from the realm, the client could send the requested RPID using Server Name Indication.

### Option 2: Mandate RPID to equal Realm of the Username

The second option would be to mandate that the RPID is equal to the realm portion of the username.
This restricts options on how to use EAP-FIDO and may cause unnecessary difficulties in routing, if the convinient routing domain (e.g. the registered domain for a company) should not be used as RPID due to security concerns, or different RPIDs should be used under the same routing realm.

### Option 3: RPID is determined by the server and sent before the TLS handshake

Since the RPID plays an important role in the decision whether or not the certificate sent by the server is to be trusted, the RPID should be determined before the TLS handshake.
The server could determine the RPID based on the outer username and send it as payload in the EAP-TLS Start packet.
This way, the client has a clear indication as to whether or not to trust the server certificate sent in the subsequent TLS handshake.

However, this opens up some security issues that are yet to be investigated, since the RPID could be modified by an on-path attacker.

### Option 4: RPID is determined by the server and sent after the TLS handshake

With this option, the problem is that the client needs to cache the server certificate in order to determine if the RPID is valid. for the given certificate, unless the rules for certificate verification and RPID determination specify it otherwise.
One possibility to circumvent this would be to allow the server certificate names and the RPID to deviate, but validate both against the realm of the outer username, e.g. a realm of example.com with a server certificate for radius.example.com and the FIDO RPID fido.example.com.

This, however, adds a whole lot more of security concerns, especially in environments with different independent devisions under the same domain suffix.

# Document Status

Note to RFC Editor: Remove this section before publication.

## Change History

-00: Initial draft version

## Missing Specs

* Error codes and Error handling
* Key derivation for i.e. WPA2
  * Will be exported from TLS layer, maybe include some information from the FIDO exchange to bind it to the FIDO exchange?

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
